#! /usr/bin/env python3

import base64
import hashlib
import io
import os
import umsgpack

import nacl.bindings

# ./encrypt.py
from encrypt import json_repr, chunks_with_empty


def sign(message):
    real_pk, real_sk = nacl.bindings.crypto_sign_keypair()
    salt = os.urandom(16)
    header = [
        "saltbox",
        [1, 0],
        1,
        real_pk,
        salt,
        ]
    output = io.BytesIO()
    umsgpack.pack(header, output)

    for chunk in chunks_with_empty(message, 50):
        payload_digest = hashlib.sha512(salt + chunk).digest()
        payload_sig_text = b"SaltBox\0attached signature\0" + payload_digest
        payload_sig = nacl.bindings.crypto_sign(payload_sig_text, real_sk)
        detached_payload_sig = payload_sig[:64]
        packet = [
            detached_payload_sig,
            chunk,
        ]
        umsgpack.pack(packet, output)

    output_bytes = output.getvalue()
    print(base64.b64encode(output_bytes))
    return output_bytes


def detached_sign(message):
    real_pk, real_sk = nacl.bindings.crypto_sign_keypair()
    salt = os.urandom(16)
    message_digest = hashlib.sha512(salt + message).digest()
    message_sig_text = b"SaltBox\0detached signature\0" + message_digest
    message_sig = nacl.bindings.crypto_sign(message_sig_text, real_sk)
    detached_message_sig = message_sig[:64]

    header = [
        "saltbox",
        [1, 0],
        1,
        real_pk,
        salt,
        detached_message_sig,
        ]
    output_bytes = umsgpack.packb(header)
    print(base64.b64encode(output_bytes))
    return output_bytes


def verify(signed_message):
    input = io.BytesIO(signed_message)
    output = io.BytesIO()
    header = umsgpack.unpack(input)
    print(json_repr(header))
    [
        name,
        [major, minor],
        mode,
        real_pk,
        salt,
    ] = header

    while True:
        payload_packet = umsgpack.unpack(input)
        print(json_repr(payload_packet))
        [detached_payload_sig, chunk] = payload_packet
        payload_digest = hashlib.sha512(salt + chunk).digest()
        payload_sig_text = b"SaltBox\0attached signature\0" + payload_digest
        payload_sig = detached_payload_sig + payload_sig_text
        nacl.bindings.crypto_sign_open(payload_sig, real_pk)
        if chunk == b"":
            break
        output.write(chunk)

    verified_message = output.getvalue()
    print(verified_message)
    return verified_message


def detached_verify(message, signature):
    header = umsgpack.unpackb(signature)
    print(json_repr(header))
    [
        name,
        [major, minor],
        mode,
        real_pk,
        salt,
        detached_message_sig,
    ] = header

    message_digest = hashlib.sha512(salt + message).digest()
    message_sig_text = b"SaltBox\0detached signature\0" + message_digest
    message_sig = detached_message_sig + message_sig_text
    nacl.bindings.crypto_sign_open(message_sig, real_pk)

    print(message)
    return message


def main():
    message = (b"I swear to tell the truth, the whole truth, and nothing " +
               b"but the truth, so help me God.")
    signed_message = sign(message)
    verify(signed_message)

    print()
    detached_sig = detached_sign(message)
    detached_verify(message, detached_sig)

if __name__ == '__main__':
    main()
