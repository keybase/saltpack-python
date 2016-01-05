#! /usr/bin/env python3

import binascii
import io
import json
import os
import sys

import umsgpack
import libnacl
import docopt

import armor

__doc__ = '''\
Usage:
    encrypt.py encrypt [<private>] [<recipients>...] [options]
    encrypt.py decrypt [<private>] [options]

If no private key is given, the default is 32 zero bytes. If no recipients are
given, the default is the sender's own public key.

Options:
    -a --armor          encode/decode with SaltPack armor
    -c --chunk=<size>   size of payload chunks, default 1 MB
    -m --message=<msg>  message text, instead of reading stdin
    --debug             debug mode
'''

FORMAT_VERSION = 1

DEBUG_MODE = False

# Hardcode the keys for everyone involved.
# ----------------------------------------

jack_private = b'\xaa' * 32


# Utility functions.
# ------------------

def chunks_with_empty(message, chunk_size):
    'The last chunk is empty, which signifies the end of the message.'
    chunk_start = 0
    chunks = []
    while chunk_start < len(message):
        chunks.append(message[chunk_start:chunk_start+chunk_size])
        chunk_start += chunk_size
    # empty chunk
    chunks.append(b'')
    return chunks


def json_repr(obj):
    # We need to repr everything that JSON doesn't directly support,
    # particularly bytes.
    def _recurse_repr(obj):
        if isinstance(obj, (list, tuple)):
            return [_recurse_repr(x) for x in obj]
        elif isinstance(obj, dict):
            return {_recurse_repr(key): _recurse_repr(val)
                    for key, val in obj.items()}
        elif isinstance(obj, bytes):
            try:
                obj.decode('utf8')
                return repr(obj)
            except UnicodeDecodeError:
                return tohex(obj)
        else:
            return obj
    return json.dumps(_recurse_repr(obj), indent='  ')


def counter(i):
    'Turn the number into a 64-bit big-endian unsigned representation.'
    return i.to_bytes(8, 'big')


def tohex(b):
    return binascii.hexlify(b).decode()


def debug(*args):
    # hexify any bytes values
    args = list(args)
    for i, arg in enumerate(args):
        if isinstance(arg, bytes):
            args[i] = tohex(args[i])
    # print to stderr, if we're in debug mode
    if DEBUG_MODE:
        print(*args, file=sys.stderr)


# All the important bits!
# -----------------------

def encrypt(sender_private, recipient_public_keys, message, chunk_size):
    sender_public = libnacl.crypto_scalarmult_base(sender_private)
    ephemeral_private = os.urandom(32)
    ephemeral_public = libnacl.crypto_scalarmult_base(ephemeral_private)
    nonce_prefix_preimage = (
        b"SaltPack\0" +
        b"encryption nonce prefix\0" +
        ephemeral_public)
    nonce_prefix = libnacl.crypto_hash(nonce_prefix_preimage)[:16]
    message_key = os.urandom(32)

    keys = [sender_public, message_key]
    keys_bytes = umsgpack.packb(keys)
    header_nonce = nonce_prefix + counter(0)

    recipient_pairs = []
    recipient_beforenms = {}
    for recipient_public in recipient_public_keys:
        # The recipient box holds the sender's long-term public key and the
        # symmetric message encryption key. It's encrypted for each recipient
        # with the ephemeral private key.
        recipient_box = libnacl.crypto_box(
            msg=keys_bytes,
            nonce=header_nonce,
            pk=recipient_public,
            sk=ephemeral_private)
        # None is for the recipient public key, which is optional.
        pair = [None, recipient_box]
        recipient_pairs.append(pair)

        # Precompute the shared secret to speed up payload packet encryption.
        beforenm = libnacl.crypto_box_beforenm(
            pk=recipient_public,
            sk=sender_private)
        recipient_beforenms[recipient_public] = beforenm

    header = [
        "SaltBox",  # format name
        [1, 0],     # major and minor version
        0,          # mode (encryption, as opposed to signing/detached)
        ephemeral_public,
        recipient_pairs,
    ]
    output = io.BytesIO()
    output.write(umsgpack.packb(header))

    # Write the chunks.
    for chunknum, chunk in enumerate(chunks_with_empty(message, chunk_size)):
        payload_nonce = nonce_prefix + counter(chunknum + 1)
        payload_secretbox = libnacl.crypto_secretbox(
            msg=chunk,
            nonce=payload_nonce,
            key=message_key)
        # Authenticate the hash of the payload for each recipient.
        payload_hash = libnacl.crypto_hash(payload_secretbox)
        hash_authenticators = []
        for recipient_public in recipient_public_keys:
            beforenm = recipient_beforenms[recipient_public]
            hash_box = libnacl.crypto_box_afternm(
                msg=payload_hash,
                nonce=payload_nonce,
                k=beforenm)
            hash_authenticators.append(hash_box[:16])
        packet = [
            hash_authenticators,
            payload_secretbox,
        ]
        output.write(umsgpack.packb(packet))

    return output.getvalue()


def decrypt(input, recipient_private):
    stream = io.BytesIO(input)
    # Parse the header.
    header = umsgpack.unpack(stream)
    debug('header:', json_repr(header))
    [
        format_name,
        [major_version, minor_version],
        mode,
        ephemeral_public,
        recipient_pairs,
        *_,  # ignore additional elements
    ] = header
    nonce_prefix_preimage = (
        b"SaltPack\0" +
        b"encryption nonce prefix\0" +
        ephemeral_public)
    nonce_prefix = libnacl.crypto_hash(nonce_prefix_preimage)[:16]
    ephemeral_beforenm = libnacl.crypto_box_beforenm(
        pk=ephemeral_public,
        sk=recipient_private)
    header_nonce = nonce_prefix + counter(0)
    debug('nonce:', header_nonce)

    # Try decrypting each sender box, until we find the one that works.
    for recipient_index, pair in enumerate(recipient_pairs):
        [_, recipient_box, *_] = pair
        try:
            keys_bytes = libnacl.crypto_box_open_afternm(
                ctxt=recipient_box,
                nonce=header_nonce,
                k=ephemeral_beforenm)
            break
        except ValueError:
            continue
    else:
        raise RuntimeError('Failed to find matching recipient.')

    # Unpack the sender key and the message encryption key.
    keys = umsgpack.unpackb(keys_bytes)
    sender_public, message_key = keys

    # Precompute the shared secret to speed up payload decryption.
    sender_beforenm = libnacl.crypto_box_beforenm(
        pk=sender_public,
        sk=recipient_private)

    debug('nonce prefix', nonce_prefix)
    debug('recipient index:', recipient_index)
    debug('sender key:', sender_public)
    debug('message key:', message_key)

    # Decrypt each of the packets.
    output = io.BytesIO()
    packetnum = 1
    while True:
        payload_nonce = nonce_prefix + counter(packetnum)
        packet = umsgpack.unpack(stream)
        debug('packet:', json_repr(packet))
        [hash_authenticators, payload_secretbox, *_] = packet
        hash_authenticator = hash_authenticators[recipient_index]

        # Verify the secretbox hash.
        payload_hash = libnacl.crypto_hash(payload_secretbox)
        hash_box = libnacl.crypto_box_afternm(
            msg=payload_hash,
            nonce=payload_nonce,
            k=sender_beforenm)
        our_authenticator = hash_box[:16]

        debug('nonce:', payload_nonce)
        debug('payload hash', payload_hash)
        debug('hash authenticator:', our_authenticator)

        verified = libnacl.crypto_verify_16(
            our_authenticator, hash_authenticator)
        assert verified, "The payload hash authenticator doesn't match."

        # Open the payload secretbox.
        chunk = libnacl.crypto_secretbox_open(
            ctxt=payload_secretbox,
            nonce=payload_nonce,
            key=message_key)
        output.write(chunk)

        debug('chunk:', repr(chunk))

        # The empty chunk signifies the end of the message.
        if chunk == b'':
            break

        packetnum += 1

    return output.getvalue()


def get_private(args):
    if args['<private>']:
        private = binascii.unhexlify(args['<private>'])
        assert len(private) == 32
        return private
    else:
        return b'\0'*32


def get_recipients(args):
    if args['<recipients>']:
        recipients = []
        for recipient in args['<recipients>']:
            key = binascii.unhexlify(recipient)
            assert len(key) == 32
            recipients.append(key)
        return recipients
    else:
        # Without explicit recipients, just send to yourself.
        private = get_private(args)
        public = libnacl.crypto_scalarmult_base(private)
        return [public]


def do_encrypt(args):
    message = args['--message']
    if message is None:
        encoded_message = sys.stdin.buffer.read()
    else:
        encoded_message = message.encode('utf8')
    sender = get_private(args)
    if args['--chunk']:
        chunk_size = int(args['--chunk'])
    else:
        chunk_size = 10**6
    recipients = get_recipients(args)
    output = encrypt(
        sender,
        recipients,
        encoded_message,
        chunk_size)
    if args['--armor']:
        output = (armor.armor(output) + '\n').encode()
    sys.stdout.buffer.write(output)


def do_decrypt(args):
    message = sys.stdin.buffer.read()
    if args['--armor']:
        message = armor.dearmor(message.decode())
    private = get_private(args)
    decoded_message = decrypt(message, private)
    sys.stdout.buffer.write(decoded_message)


def main():
    global DEBUG_MODE
    args = docopt.docopt(__doc__)
    DEBUG_MODE = args['--debug']
    if args['encrypt']:
        do_encrypt(args)
    else:
        do_decrypt(args)


if __name__ == '__main__':
    main()
