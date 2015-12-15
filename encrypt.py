#! /usr/bin/env python3

import base64
from hashlib import sha512
import io
import json
import os

import umsgpack
import nacl.bindings
from nacl.exceptions import CryptoError
import docopt

__doc__ = '''\
Usage:
    encrypt.py [<message>] [--recipients=<num_recipients>]
               [--chunk=<chunk_size>]
'''

FORMAT_VERSION = 1

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
                return repr(base64.b64encode(obj))
        else:
            return obj
    return json.dumps(_recurse_repr(obj), indent='  ')


def counter(i):
    'Turn the number into a 64-bit big-endian unsigned representation.'
    return i.to_bytes(8, 'big')


# All the important bits!
# -----------------------

def encrypt(sender_private, recipient_public_keys, message, chunk_size):
    sender_public = nacl.bindings.crypto_scalarmult_base(sender_private)
    ephemeral_private = os.urandom(32)
    ephemeral_public = nacl.bindings.crypto_scalarmult_base(ephemeral_private)
    nonce_prefix_preimage = (
        b"SaltPack\0" +
        b"encryption nonce prefix\0" +
        ephemeral_public)
    nonce_prefix = sha512(nonce_prefix_preimage).digest()[:16]
    encryption_key = os.urandom(32)

    recipient_tuples = []
    recipient_beforenms = {}
    for recipient_public in recipient_public_keys:
        # The sender_box holds the sender's long-term public key. It's
        # encrypted for each recipient with the ephemeral private key.
        sender_box = nacl.bindings.crypto_box(
            message=sender_public,
            nonce=nonce_prefix + counter(0),
            pk=recipient_public,
            sk=ephemeral_private)

        # The key_box holds the randomly generated encryption_key. It's
        # encrypted for each recipient with the sender's long-term private key.
        beforenm = nacl.bindings.crypto_box_beforenm(
            pk=recipient_public,
            sk=sender_private)
        recipient_beforenms[recipient_public] = beforenm
        key_box = nacl.bindings.crypto_box_afternm(
            message=encryption_key,
            nonce=nonce_prefix + counter(1),
            k=beforenm)

        # None is for the recipient public key, which is optional.
        recipient_tuple = [None, sender_box, key_box]
        recipient_tuples.append(recipient_tuple)

    header = [
        "SaltBox",  # format name
        [1, 0],     # major and minor version
        0,          # mode (encryption, as opposed to signing/detached)
        ephemeral_public,
        recipient_tuples,
    ]
    output = io.BytesIO()
    output.write(umsgpack.packb(header))

    # Write the chunks.
    for packetnum, chunk in enumerate(chunks_with_empty(message, chunk_size)):
        payload_nonce = nonce_prefix + counter(packetnum + 2)
        payload_secretbox = nacl.bindings.crypto_secretbox(
            message=chunk,
            nonce=payload_nonce,
            key=encryption_key)
        payload_tag = payload_secretbox[:16]  # the Poly1305 authenticator
        stripped_payload_secretbox = payload_secretbox[16:]
        tag_boxes = []
        for recipient_public in recipient_public_keys:
            # Encrypt the payload_tag for each recipient. This isn't because we
            # want to keep the tag secret, but because:
            #   1) We want to authenticate the tag, to prove the sender
            #      actually wrote it.
            #   2) We want to force implementations to verify that.
            beforenm = recipient_beforenms[recipient_public]
            tag_box = nacl.bindings.crypto_box_afternm(
                message=payload_tag,
                nonce=payload_nonce,
                k=beforenm)
            tag_boxes.append(tag_box)
        packet = [
            tag_boxes,
            stripped_payload_secretbox,
        ]
        output.write(umsgpack.packb(packet))

    return output.getvalue()


def decrypt(input, recipient_private):
    stream = io.BytesIO(input)
    # Parse the header.
    header = umsgpack.unpack(stream)
    print('Header: ', end='')
    print(json_repr(header))
    [
        format_name,
        [major_version, minor_version],
        mode,
        ephemeral_public,
        recipient_tuples,
    ] = header
    nonce_prefix_preimage = (
        b"SaltPack\0" +
        b"encryption nonce prefix\0" +
        ephemeral_public)
    nonce_prefix = sha512(nonce_prefix_preimage).digest()[:16]
    ephemeral_beforenm = nacl.bindings.crypto_box_beforenm(
        pk=ephemeral_public,
        sk=recipient_private)

    # Try decrypting each sender box, until we find the one that works.
    for recipient_index, recipient_tuple in enumerate(recipient_tuples):
        [_, sender_box, key_box] = recipient_tuple
        try:
            sender_public = nacl.bindings.crypto_box_open_afternm(
                ciphertext=sender_box,
                nonce=nonce_prefix + counter(0),
                k=ephemeral_beforenm)
            break
        except CryptoError:
            continue
    else:
        raise RuntimeError('Failed to find matching recipient.')

    # Decrypt the encryption_key using sender_public.
    sender_beforenm = nacl.bindings.crypto_box_beforenm(
        pk=sender_public,
        sk=recipient_private)
    encryption_key = nacl.bindings.crypto_box_open_afternm(
        ciphertext=key_box,
        nonce=nonce_prefix + counter(1),
        k=sender_beforenm)

    # Decrypt each of the packets.
    output = io.BytesIO()
    packetnum = 2
    while True:
        payload_nonce = nonce_prefix + counter(packetnum)
        packet = umsgpack.unpack(stream)
        print('Packet: ', end='')
        print(json_repr(packet))
        [tag_boxes, stripped_payload_secretbox] = packet
        tag_box = tag_boxes[recipient_index]

        # Open the tag box.
        payload_tag = nacl.bindings.crypto_box_open_afternm(
            ciphertext=tag_box,
            nonce=payload_nonce,
            k=sender_beforenm)

        # Prepend the tag and open the payload secretbox.
        payload_secretbox = payload_tag + stripped_payload_secretbox
        chunk = nacl.bindings.crypto_secretbox_open(
            ciphertext=payload_secretbox,
            nonce=payload_nonce,
            key=encryption_key)
        output.write(chunk)
        print('Chunk:', chunk)

        # The empty chunk signifies the end of the message.
        if chunk == b'':
            break

        packetnum += 1

    return output.getvalue()


def main():
    default_message = b'The Magic Words are Squeamish Ossifrage'
    args = docopt.docopt(__doc__)
    message = args['<message>']
    if message is None:
        encoded_message = default_message
    else:
        encoded_message = message.encode('utf8')
    recipients_len = int(args.get('--recipients') or 1)
    recipient_private_keys = [os.urandom(32) for i in range(recipients_len)]
    recipient_public_keys = [nacl.bindings.crypto_scalarmult_base(r)
                             for r in recipient_private_keys]
    chunk_size = int(args.get('--chunk') or 100)
    output = encrypt(
        jack_private,
        recipient_public_keys,
        encoded_message,
        chunk_size)
    print(base64.b64encode(output).decode())
    print('-----------------------------------------')
    decoded_message = decrypt(output, recipient_private_keys[0])
    print('message:', decoded_message)


if __name__ == '__main__':
    main()
