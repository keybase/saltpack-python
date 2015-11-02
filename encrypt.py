#! /usr/bin/env python3

import base64
import hmac
import io
import json
import os
import textwrap

import umsgpack
import nacl.bindings

FORMAT_VERSION = 1

# Hardcode the keys for everyone involved.
# ----------------------------------------

jack_private = b'\xaa' * 32
jack_public = nacl.bindings.crypto_scalarmult_base(jack_private)

max_private = b'\xbb' * 32
max_public = nacl.bindings.crypto_scalarmult_base(max_private)

chris_private = b'\xcc' * 32
chris_public = nacl.bindings.crypto_scalarmult_base(chris_private)


# Utility functions.
# ------------------

def chunks_with_empty(message):
    'The last chunk is empty, which signifies the end of the message.'
    chunk_size = 100
    chunk_start = 0
    chunks = []
    while chunk_start < len(message):
        chunks.append(message[chunk_start:chunk_start+chunk_size])
        chunk_start += chunk_size
    # empty chunk
    chunks.append(b'')
    return chunks


def write_framed_msgpack(stream, obj):
    msgpack_bytes = umsgpack.packb(obj)
    frame = umsgpack.packb(len(msgpack_bytes))
    stream.write(frame)
    stream.write(msgpack_bytes)


def read_framed_msgpack(stream):
    length = umsgpack.unpack(stream)
    print(length)
    # We discard the frame length and stream on.
    obj = umsgpack.unpack(stream)
    print(json_repr(obj))
    return obj


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

def encode(sender_private, recipient_groups, message):
    sender_public = nacl.bindings.crypto_scalarmult_base(sender_private)
    encryption_key = os.urandom(32)
    mac_keys = []
    # We will skip MACs entirely if there's only going to be one MAC key. In
    # that case, Box() gives the same guarantees.
    need_macs = (len(recipient_groups) > 1)
    recipients_list = []
    # First 16 bytes of the recipients nonce is random. The last 8 are the
    # recipient counter.
    recipients_nonce_start = os.urandom(16)
    recipient_num = 0
    for group_num, group in enumerate(recipient_groups):
        if need_macs:
            mac_key = os.urandom(32)
            mac_keys.append(mac_key)
        for recipient in group:
            key_list = [encryption_key]
            if need_macs:
                key_list = [
                    encryption_key,
                    group_num,
                    mac_key,
                ]
            else:
                key_list = [
                    encryption_key,
                ]
            packed_list = umsgpack.packb(key_list)
            recipient_nonce = (recipients_nonce_start +
                               recipient_num.to_bytes(8, byteorder="big"))
            recipient_num += 1
            boxed_list = nacl.bindings.crypto_box(
                message=packed_list,
                nonce=recipient_nonce,
                sk=sender_private,
                pk=recipient)
            recipients_list.append([recipient, boxed_list])
    header = [
        FORMAT_VERSION,
        sender_public,
        recipients_nonce_start,
        recipients_list,
    ]
    output = io.BytesIO()
    write_framed_msgpack(output, header)

    # Write the chunks.
    for chunknum, chunk in enumerate(chunks_with_empty(message)):
        nonce = chunknum.to_bytes(24, byteorder='big')
        # Box and strip the nonce.
        boxed_chunk = nacl.bindings.crypto_secretbox(
            message=chunk,
            nonce=nonce,
            key=encryption_key)
        macs = []
        if need_macs:
            authenticator = boxed_chunk[:16]
            for mac_key in mac_keys:
                hmac_obj = hmac.new(mac_key, digestmod='sha512')
                hmac_obj.update(authenticator)
                macs.append(hmac_obj.digest()[:32])
        chunk_list = [
            macs,
            boxed_chunk,
        ]
        write_framed_msgpack(output, chunk_list)

    return output.getvalue()


def decode(input, recipient_private):
    stream = io.BytesIO(input)
    # Parse the header.
    header = read_framed_msgpack(stream)
    version, sender_public, recipients_nonce_start, recipients = header
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
    packed_list = nacl.bindings.crypto_box_open(
        ciphertext=boxed_keys,
        nonce=recipient_nonce,
        sk=recipient_private,
        pk=sender_public)
    key_list = umsgpack.unpackb(packed_list)
    if len(key_list) > 1:
        encryption_key, group_num, mac_key = key_list
    else:
        encryption_key = key_list[0]
        group_num, mac_key = None, None
    print(textwrap.indent('key list: ' + json_repr(key_list), '### '))
    # Unbox each of the chunks.
    chunknum = 0
    output = io.BytesIO()
    while True:
        nonce = chunknum.to_bytes(24, byteorder='big')
        chunk_list = read_framed_msgpack(stream)
        macs, boxed_chunk = chunk_list
        # Check the MAC.
        if mac_key is not None:
            their_mac = macs[group_num]
            authenticator = boxed_chunk[:16]
            hmac_obj = hmac.new(mac_key, digestmod='sha512')
            hmac_obj.update(authenticator)
            our_mac = hmac_obj.digest()[:32]
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
    message = b'The Magic Words are Squeamish Ossifrage'
    output = encode(jack_private, [[max_public]], message)
    print(base64.b64encode(output).decode())
    print('-----------------------------------------')
    decoded_message = decode(output, max_private)
    print('message:', decoded_message)


if __name__ == '__main__':
    main()
