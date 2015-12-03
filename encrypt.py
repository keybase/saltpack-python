#! /usr/bin/env python3

import base64
from hashlib import sha512
import hmac
import io
import json
import os
import textwrap

import umsgpack
import nacl.bindings
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
                sk=ephemeral_private,
                pk=recipient)

            # The keys box encrypts the encryption_key and the mac_key. It's
            # sent using sender_private.
            keys = [
                encryption_key,
                group_num,  # TODO: xor this with something
                mac_key,
            ]
            keys_bytes = umsgpack.packb(keys)
            keys_box_counter_bytes = (2*recipient_num + 1).to_bytes(4, 'big')
            keys_box_nonce = nonce_start + keys_box_counter_bytes
            keys_box = nacl.bindings.crypto_box(
                message=keys_bytes,
                nonce=keys_box_nonce,
                sk=sender_private,
                pk=recipient)

            # None is for the recipient public key, which is optional.
            recipient_set = [None, sender_box, keys_box]
            recipient_sets.append(recipient_set)
            recipient_num += 1

    header = [
        "sillybox",  # format name
        1,           # version
        ephemeral_public,
        recipient_sets,
    ]
    output = io.BytesIO()
    output.write(umsgpack.packb(header))

    # Write the chunks.
    for chunknum, chunk in enumerate(chunks_with_empty(message, chunk_size)):
        nonce = chunknum.to_bytes(24, byteorder='big')
        chunk_box = nacl.bindings.crypto_secretbox(
            message=chunk,
            nonce=nonce,
            key=encryption_key)
        chunk_tag = chunk_box[:16]  # the Poly1305 authenticator
        macs = []
        for mac_key in mac_keys:
            chunk_tag_hmac = hmac.new(
                key=mac_key,
                msg=chunk_tag,
                digestmod='sha512',
                ).digest()
            # Only take the first 32 bytes of HMAC-SHA512, as NaCl does.
            macs.append(chunk_tag_hmac[:32])
        packet = [
            macs,
            chunk_box,
        ]
        output.write(umsgpack.packb(packet))

    return output.getvalue()


def decrypt(input, recipient_private):
    stream = io.BytesIO(input)
    # Parse the header.
    header = read_framed_msgpack(stream)
    version = header['version']
    assert version == 1
    sender_public = header['sender']
    recipients_nonce_start = header['nonce']
    recipients = header['recipients']
    # Find this recipient's key box.
    recipient_public = nacl.bindings.crypto_scalarmult_base(recipient_private)
    recipient_num = 0
    for pub, boxed_keys in recipients:
        if pub == recipient_public:
            break
        recipient_num += 1
    else:
        raise RuntimeError('recipient key not found')
    # Unbox the recipient's keys.
    recipient_nonce = (recipients_nonce_start +
                       recipient_num.to_bytes(8, byteorder='big'))
    packed_keys = nacl.bindings.crypto_box_open(
        ciphertext=boxed_keys,
        nonce=recipient_nonce,
        sk=recipient_private,
        pk=sender_public)
    keys = umsgpack.unpackb(packed_keys)
    print(textwrap.indent('keys: ' + json_repr(keys), '### '))
    encryption_key = keys['encryption_key']
    mac_group = keys.get('mac_group')
    mac_key = keys.get('mac_key')
    # Unbox each of the chunks.
    chunknum = 0
    output = io.BytesIO()
    while True:
        nonce = chunknum.to_bytes(24, byteorder='big')
        chunk_map = read_framed_msgpack(stream)
        macs = chunk_map['macs']
        boxed_chunk = chunk_map['chunk']
        # Check the MAC.
        if mac_key is not None:
            their_mac = macs[mac_group]
            authenticator = boxed_chunk[:16]
            hmac_obj = hmac.new(mac_key, digestmod='sha512')
            hmac_obj.update(authenticator)
            our_mac = hmac_obj.digest()[:16]
            if not hmac.compare_digest(their_mac, our_mac):
                raise RuntimeError("MAC mismatch!")
        # Prepend the nonce and decrypt.
        chunk = nacl.bindings.crypto_secretbox_open(
            ciphertext=boxed_chunk,
            nonce=nonce,
            key=encryption_key)
        print('### chunk {}: {}'.format(chunknum, chunk))
        if chunk == b'':
            break
        output.write(chunk)
        chunknum += 1
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
