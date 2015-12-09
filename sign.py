#! /usr/bin/env python3

import base64
import hashlib
import io
import umsgpack
import nacl.bindings

# ./encrypt.py
from encrypt import json_repr, chunks_with_empty


prefix = b"SALTBOXPREFIX\0"


def sign(message):
    real_pk, real_sk = nacl.bindings.crypto_sign_keypair()
    ephemeral_pk, ephemeral_sk = nacl.bindings.crypto_sign_keypair()
    delegation_sig_text = prefix + b"DELEGATION\0" + ephemeral_pk
    delegation_sig = nacl.bindings.crypto_sign(delegation_sig_text, real_sk)
    detached_delegation_sig = delegation_sig[:64]
    header = [
        "saltbox",
        [1, 0],
        1,
        real_pk,
        ephemeral_pk,
        detached_delegation_sig,
        ]
    output = io.BytesIO()
    umsgpack.pack(header, output)

    for chunk in chunks_with_empty(message, 50):
        payload_digest = hashlib.sha512(chunk).digest()
        payload_sig_text = prefix + b"ATTACHED\0" + payload_digest
        payload_sig = nacl.bindings.crypto_sign(payload_sig_text, ephemeral_sk)
        detached_payload_sig = payload_sig[:64]
        packet = [
            detached_payload_sig,
            chunk,
        ]
        umsgpack.pack(packet, output)

    output_bytes = output.getvalue()
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
        ephemeral_pk,
        detached_delegation_sig,
    ] = header
    delegation_sig_text = prefix + b"DELEGATION\0" + ephemeral_pk
    delegation_sig = detached_delegation_sig + delegation_sig_text
    nacl.bindings.crypto_sign_open(delegation_sig, real_pk)

    while True:
        payload_packet = umsgpack.unpack(input)
        print(json_repr(payload_packet))
        [detached_payload_sig, chunk] = payload_packet
        payload_digest = hashlib.sha512(chunk).digest()
        payload_sig_text = prefix + b"ATTACHED\0" + payload_digest
        payload_sig = detached_payload_sig + payload_sig_text
        nacl.bindings.crypto_sign_open(payload_sig, ephemeral_pk)
        if chunk == b"":
            break
        output.write(chunk)

    verified_message = output.getvalue()
    print(verified_message)
    return verified_message


def main():
    message = (b"I swear to tell the truth, the whole truth, and nothing " +
               b"but the truth, so help me God.")
    signed_message = sign(message)
    verify(signed_message)

if __name__ == '__main__':
    main()
