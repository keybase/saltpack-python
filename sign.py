#! /usr/bin/env python3

import binascii
import hashlib
import io
import os
import sys
import umsgpack

import docopt
import libnacl

# ./encrypt.py
from encrypt import json_repr, chunks_with_empty

# ./armor.py
import armor

__doc__ = '''\
Usage:
    sign.py sign [<private>] [options]
    sign.py verify [options]

If no private key is given, the default is random.

Options:
    -a --armor             encode/decode with saltpack armor
    -c --chunk=<size>      size of payload chunks, default 1 MB
    -d --detached          make a detached signature
    -m --message=<msg>     message text, instead of reading stdin
    -s --signature=<file>  verify with a detached signature
    --debug                debug mode
'''

DEBUG_MODE = False


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


def write_header(public_key, mode, output):
    nonce = os.urandom(32)
    header = [
        "saltpack",
        [1, 0],
        mode,
        public_key,
        nonce,
    ]
    header_bytes = umsgpack.packb(header)
    header_hash = hashlib.sha512(header_bytes).digest()
    umsgpack.pack(header_bytes, output)
    return header_hash


def read_header(stream):
    header_bytes = umsgpack.unpack(stream)
    header_hash = hashlib.sha512(header_bytes).digest()
    header = umsgpack.unpackb(header_bytes)
    debug("header packet:", json_repr(header))
    debug("header hash:", json_repr(header_hash))
    [
        name,
        [major, minor],
        mode,
        public_key,
        nonce,
        *_,  # ignore additional elements
    ] = header
    return public_key, header_hash


def sign_attached(message, private_key, chunk_size):
    output = io.BytesIO()
    public_key = private_key[32:]
    header_hash = write_header(public_key, 1, output)

    packetnum = 0
    for chunk in chunks_with_empty(message, chunk_size):
        packetnum_64 = packetnum.to_bytes(8, 'big')
        payload_digest = hashlib.sha512(
            header_hash + packetnum_64 + chunk).digest()
        payload_sig_text = b"saltpack attached signature\0" + payload_digest
        payload_sig = libnacl.crypto_sign(payload_sig_text, private_key)
        detached_payload_sig = payload_sig[:64]
        packet = [
            detached_payload_sig,
            chunk,
        ]
        umsgpack.pack(packet, output)
        packetnum += 1

    return output.getvalue()


def sign_detached(message, private_key):
    output = io.BytesIO()
    public_key = private_key[32:]
    header_hash = write_header(public_key, 2, output)
    message_digest = hashlib.sha512(header_hash + message).digest()
    message_sig_text = b"saltpack detached signature\0" + message_digest
    message_sig = libnacl.crypto_sign(message_sig_text, private_key)
    detached_message_sig = message_sig[:64]
    umsgpack.pack(detached_message_sig, output)
    return output.getvalue()


def verify_attached(message):
    input = io.BytesIO(message)
    output = io.BytesIO()
    public_key, header_hash = read_header(input)

    packetnum = 0
    while True:
        payload_packet = umsgpack.unpack(input)
        debug("payload packet:", json_repr(payload_packet))
        [detached_payload_sig, chunk, *_] = payload_packet
        packetnum_64 = packetnum.to_bytes(8, 'big')
        debug("packet number:", packetnum_64)
        payload_digest = hashlib.sha512(
            header_hash + packetnum_64 + chunk).digest()
        debug("digest:", payload_digest)
        payload_sig_text = b"saltpack attached signature\0" + payload_digest
        payload_sig = detached_payload_sig + payload_sig_text
        libnacl.crypto_sign_open(payload_sig, public_key)
        if chunk == b"":
            break
        output.write(chunk)
        packetnum += 1

    verified_message = output.getvalue()
    return verified_message


def verify_detached(message, signature):
    input = io.BytesIO(signature)
    public_key, header_hash = read_header(input)

    detached_message_sig = umsgpack.unpack(input)
    debug("sig:", detached_message_sig)
    message_digest = hashlib.sha512(header_hash + message).digest()
    debug("digest:", message_digest)
    message_sig_text = b"saltpack detached signature\0" + message_digest
    message_sig = detached_message_sig + message_sig_text
    libnacl.crypto_sign_open(message_sig, public_key)
    return message


def do_sign(args):
    message = args['--message']
    # Get the message bytes.
    if message is None:
        encoded_message = sys.stdin.buffer.read()
    else:
        encoded_message = message.encode('utf8')
    # Get the private key.
    if args['<private>']:
        private_key = binascii.unhexlify(args['<private>'])
        assert len(private_key) == 64
    else:
        private_key = libnacl.crypto_sign_keypair()[1]
    # Get the chunk size.
    if args['--chunk']:
        chunk_size = int(args['--chunk'])
    else:
        chunk_size = 10**6
    # Sign the message.
    if args['--detached']:
        message_type = "DETACHED SIGNATURE"
        output = sign_detached(encoded_message, private_key)
    else:
        message_type = "ATTACHED SIGNATURE"
        output = sign_attached(encoded_message, private_key, chunk_size)
    # Armor the message.
    if args['--armor']:
        output = (armor.armor(output, message_type=message_type) +
                  '\n').encode()
    sys.stdout.buffer.write(output)


def do_verify(args):
    # Read the message from stdin or --message. In attached mode this is the
    # attached signature, but in detached mode this is the plaintext, and the
    # signature needs to be specified with --signature.
    if args['--message']:
        message = args['--message'].encode()
    else:
        message = sys.stdin.buffer.read()
    # In detached mode, read the signature.
    signature_file = args['--signature']
    detached_mode = signature_file is not None
    if detached_mode:
        with open(signature_file, 'rb') as f:
            signature = f.read()
    else:
        signature = message
    # Dearmor the signature.
    if args['--armor']:
        signature = armor.dearmor(signature.decode())
    # Verify the message.
    if detached_mode:
        verify_detached(message, signature)
        print("Verified!", file=sys.stderr)
    else:
        output = verify_attached(signature)
        sys.stdout.buffer.write(output)


def main():
    global DEBUG_MODE
    args = docopt.docopt(__doc__)
    DEBUG_MODE = args['--debug']

    if args['sign']:
        do_sign(args)
    else:
        do_verify(args)


if __name__ == '__main__':
    main()
