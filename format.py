#! /usr/bin/env python3

import hmac
import io
import os

import umsgpack
import nacl.public
import nacl.secret


message = b"confirm: baraboo"

jack_private = nacl.public.PrivateKey(b'\xaa' * 32)
jack_public = jack_private.public_key

max_private = nacl.public.PrivateKey(b'\xbb' * 32)
max_public = max_private.public_key

chris_private = nacl.public.PrivateKey(b'\xcc' * 32)
chris_public = chris_private.public_key


def random_key():
    return os.urandom(32)


def random_nonce():
    return os.urandom(24)


def chunks_with_empty(message):
    'The last chunk is empty, which signifies the end of the message.'
    chunk_size = 10
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


def encode(sender_private, recipient_groups, message):
    output = io.BytesIO()
    session_key = random_key()
    mac_keys = []
    recipients_map = {}
    for groupnum, group in enumerate(recipient_groups):
        mac_key = random_key()
        mac_keys.append(mac_key)
        for recipient in group:
            per_recipient_map = {
                "session_key": session_key,
                "mac_group": groupnum,
                "mac_key": mac_key,
            }
            per_recipient_msgpack = umsgpack.packb(per_recipient_map)
            box = nacl.public.Box(sender_private, recipient)
            boxed_bytes = box.encrypt(per_recipient_msgpack, random_nonce())
            recipients_map[recipient.encode()] = boxed_bytes
    header_map = {
        "version": 1,
        "sender": sender_private.public_key.encode(),
        "recipients": recipients_map,
    }
    write_framed_msgpack(output, header_map)

    # Write the chunks.
    secretbox = nacl.secret.SecretBox(session_key)
    for chunknum, chunk in enumerate(chunks_with_empty(message)):
        nonce = chunknum.to_bytes(24, byteorder='big')
        # Box and strip the nonce.
        boxed_chunk = secretbox.encrypt(chunk, nonce)[24:]
        macs = []
        for mac_key in mac_keys:
            hmac_obj = hmac.new(mac_key, digestmod='sha512')
            hmac_obj.update(nonce)
            hmac_obj.update(boxed_chunk)
            macs.append(hmac_obj.digest()[:32])
        chunk_map = {
            'macs': macs,
            'chunk': boxed_chunk,
        }
        write_framed_msgpack(output, chunk_map)

    return output.getvalue()


def read_framed_msgpack(stream):
    umsgpack.unpack(stream)  # frame discarded
    return umsgpack.unpack(stream)


def decode(input, recipient_private):
    stream = io.BytesIO(input)
    header_map = read_framed_msgpack(stream)
    sender_public = nacl.public.PublicKey(header_map['sender'])
    recipient_public = recipient_private.public_key.encode()
    boxed_keys = header_map['recipients'][recipient_public]
    box = nacl.public.Box(recipient_private, sender_public)
    key_map = umsgpack.unpackb(box.decrypt(boxed_keys))
    session_key = key_map['session_key']
    mac_key = key_map['mac_key']
    mac_group = key_map['mac_group']
    secretbox = nacl.secret.SecretBox(session_key)
    chunknum = 0
    while True:
        nonce = chunknum.to_bytes(24, byteorder='big')
        chunk_map = read_framed_msgpack(stream)
        their_mac = chunk_map['macs'][mac_group]
        boxed_chunk = chunk_map['chunk']
        # Check the MAC.
        mac_obj = hmac.new(mac_key, digestmod='sha512')
        mac_obj.update(nonce)
        mac_obj.update(boxed_chunk)
        our_mac = mac_obj.digest()[:32]
        if not hmac.compare_digest(their_mac, our_mac):
            raise RuntimeError("MAC mismatch!")
        # Prepend the nonce and decrypt.
        chunk = secretbox.decrypt(nonce + boxed_chunk)
        print('chunk {}: {}'.format(chunknum, chunk))
        if chunk == b'':
            break
        chunknum += 1


def main():
    output = encode(jack_private, [[max_public], [chris_public]], message)
    decode(output, max_private)


if __name__ == '__main__':
    main()
