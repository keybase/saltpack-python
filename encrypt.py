#! /usr/bin/env python3

import base64
from hashlib import sha512
import hmac
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
            return base64.b64encode(obj).decode()
        else:
            return obj
    return json.dumps(_recurse_repr(obj), indent='  ')


# All the important bits!
# -----------------------

def encrypt(sender_private, recipient_groups, message, chunk_size):
    sender_public = nacl.bindings.crypto_scalarmult_base(sender_private)
    ephemeral_private = os.urandom(32)
    ephemeral_public = nacl.bindings.crypto_scalarmult_base(ephemeral_private)
    ephemeral_hash = sha512(ephemeral_public).digest()
    # The NaCl nonce is 24 bytes. We room for a 4 byte counter.
    nonce_start = ephemeral_hash[:20]
    encryption_key = os.urandom(32)
    mac_keys = []
    recipient_num = 0
    recipient_sets = []

    # Populate all the recipient sets.
    for group_num, group in enumerate(recipient_groups):
        # The mac_key will be used to authenticate the payload packets for
        # everyone in this recipient group.
        mac_key = os.urandom(32)
        mac_keys.append(mac_key)
        for recipient in group:
            # The sender box encrypts the real sender's public key. It's sent
            # using ephemeral_private.
            sender_box_counter_bytes = (2*recipient_num).to_bytes(4, 'big')
            sender_box_nonce = nonce_start + sender_box_counter_bytes
            sender_box = nacl.bindings.crypto_box(
                message=sender_public,
                nonce=sender_box_nonce,
                pk=recipient,
                sk=ephemeral_private)

            # The keys box encrypts the encryption_key and the mac_key. It's
            # sent using sender_private.
            keys = [
                encryption_key,
                group_num | (1 << 31),  # set the high bit for constant size
                mac_key,
            ]
            keys_bytes = umsgpack.packb(keys)
            keys_box_counter_bytes = (2*recipient_num + 1).to_bytes(4, 'big')
            keys_box_nonce = nonce_start + keys_box_counter_bytes
            keys_box = nacl.bindings.crypto_box(
                message=keys_bytes,
                nonce=keys_box_nonce,
                pk=recipient,
                sk=sender_private)

            # None is for the recipient public key, which is optional.
            recipient_set = [None, sender_box, keys_box]
            recipient_sets.append(recipient_set)
            recipient_num += 1

    header = [
        "sillybox",  # format name
        1,           # major version
        0,           # minor version
        0,           # mode (encryption, as opposed to signing/detached)
        ephemeral_public,
        recipient_sets,
    ]
    output = io.BytesIO()
    output.write(umsgpack.packb(header))

    # Write the chunks.
    for packetnum, chunk in enumerate(chunks_with_empty(message, chunk_size)):
        nonce = packetnum.to_bytes(24, byteorder='big')
        chunk_box = nacl.bindings.crypto_secretbox(
            message=chunk,
            nonce=nonce,
            key=encryption_key)
        chunk_tag = chunk_box[:16]  # the Poly1305 authenticator
        macs = []
        for mac_key in mac_keys:
            # Only take the first 32 bytes of HMAC-SHA512, as NaCl does.
            chunk_tag_hmac = hmac.new(
                key=mac_key,
                msg=chunk_tag,  # TODO: mix in the packet number?
                digestmod='sha512',
                ).digest()[:32]
            macs.append(chunk_tag_hmac)
        packet = [
            macs,
            chunk_box,
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
        major_version,
        minor_version,
        mode,
        ephemeral_public,
        recipients,
    ] = header
    ephemeral_hash = sha512(ephemeral_public).digest()
    ephemeral_shared = nacl.bindings.crypto_box_beforenm(
        pk=ephemeral_public,
        sk=recipient_private)
    nonce_start = ephemeral_hash[:20]

    # Try decrypting each sender box, until we find the one that works.
    for recipient_num, recipient_set in enumerate(recipients):
        [_, sender_box, keys_box] = recipient_set
        sender_box_counter_bytes = (2*recipient_num).to_bytes(4, 'big')
        sender_box_nonce = nonce_start + sender_box_counter_bytes
        try:
            sender_public = nacl.bindings.crypto_box_open_afternm(
                ciphertext=sender_box,
                nonce=sender_box_nonce,
                k=ephemeral_shared)
            break
        except CryptoError:
            continue
    else:
        raise RuntimeError('Failed to find matching recipient.')

    # Decrypt the keys_box using sender_public.
    keys_box_counter_bytes = (2*recipient_num + 1).to_bytes(4, 'big')
    keys_box_nonce = nonce_start + keys_box_counter_bytes
    keys_bytes = nacl.bindings.crypto_box_open(
        ciphertext=keys_box,
        nonce=keys_box_nonce,
        pk=sender_public,
        sk=recipient_private)
    keys = umsgpack.unpackb(keys_bytes)
    print('Keys: ', end='')
    print(json_repr(keys))
    [encryption_key, masked_mac_group, mac_key] = keys
    mac_group = masked_mac_group ^ (1 << 31)

    # Decrypt each of the packets.
    output = io.BytesIO()
    packetnum = 0
    while True:
        packet = umsgpack.unpack(stream)
        print('Packet: ', end='')
        print(json_repr(packet))
        [macs, chunk_box] = packet

        # Check the MAC.
        their_mac = macs[mac_group]
        chunk_tag = chunk_box[:16]
        chunk_tag_hmac = hmac.new(
            key=mac_key,
            msg=chunk_tag,
            digestmod='sha512',
            ).digest()[:32]
        if not hmac.compare_digest(their_mac, chunk_tag_hmac):
            raise RuntimeError("MAC mismatch!")

        # Unbox the chunk.
        nonce = packetnum.to_bytes(24, byteorder='big')
        chunk = nacl.bindings.crypto_secretbox_open(
            ciphertext=chunk_box,
            nonce=nonce,
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
    recipients_private = [os.urandom(32) for i in range(recipients_len)]
    recipients_public = [nacl.bindings.crypto_scalarmult_base(r)
                         for r in recipients_private]
    groups = [[p] for p in recipients_public]
    chunk_size = int(args.get('--chunk') or 100)
    output = encrypt(jack_private, groups, encoded_message, chunk_size)
    print(base64.b64encode(output).decode())
    print('-----------------------------------------')
    decoded_message = decrypt(output, recipients_private[0])
    print('message:', decoded_message)


if __name__ == '__main__':
    main()
