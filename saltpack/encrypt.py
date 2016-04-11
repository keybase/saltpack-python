#! /usr/bin/env python3

import binascii
import hashlib
import hmac
import io
import json
import os
import sys

import umsgpack
import nacl.bindings
from nacl.exceptions import CryptoError

from . import armor
from . import error
from .debug import debug, tohex


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


# All the important bits!
# -----------------------

SENDER_KEY_SECRETBOX_NONCE = b"saltpack_sender_key_sbox"
assert len(SENDER_KEY_SECRETBOX_NONCE) == 24

PAYLOAD_KEY_BOX_NONCE = b"saltpack_payload_key_box"
assert len(PAYLOAD_KEY_BOX_NONCE) == 24

PAYLOAD_NONCE_PREFIX = b"saltpack_ploadsb"
assert len(PAYLOAD_NONCE_PREFIX) == 16


def encrypt(sender_private, recipient_public_keys, message, chunk_size, *,
            visible_recipients=False):
    sender_public = nacl.bindings.crypto_scalarmult_base(sender_private)
    ephemeral_private = os.urandom(32)
    ephemeral_public = nacl.bindings.crypto_scalarmult_base(ephemeral_private)
    payload_key = os.urandom(32)

    sender_secretbox = nacl.bindings.crypto_secretbox(
        message=sender_public,
        nonce=SENDER_KEY_SECRETBOX_NONCE,
        key=payload_key)

    recipient_pairs = []
    for recipient_public in recipient_public_keys:
        # The recipient box holds the sender's long-term public key and the
        # symmetric message encryption key. It's encrypted for each recipient
        # with the ephemeral private key.
        payload_key_box = nacl.bindings.crypto_box(
            message=payload_key,
            nonce=PAYLOAD_KEY_BOX_NONCE,
            pk=recipient_public,
            sk=ephemeral_private)
        # None is for the recipient public key, which is optional.
        if visible_recipients:
            pair = [recipient_public, payload_key_box]
        else:
            pair = [None, payload_key_box]
        recipient_pairs.append(pair)

    header = [
        "saltpack",  # format name
        [1, 0],      # major and minor version
        0,           # mode (encryption, as opposed to signing/detached)
        ephemeral_public,
        sender_secretbox,
        recipient_pairs,
    ]
    header_bytes = umsgpack.packb(header)
    header_hash = nacl.bindings.crypto_hash(header_bytes)
    double_encoded_header_bytes = umsgpack.packb(header_bytes)
    output = io.BytesIO()
    output.write(double_encoded_header_bytes)

    # Compute the per-user MAC keys.
    recipient_mac_keys = []
    mac_keys_nonce = header_hash[:24]
    for recipient_public in recipient_public_keys:
        mac_key_box = nacl.bindings.crypto_box(
            message=b'\0'*32,
            nonce=mac_keys_nonce,
            pk=recipient_public,
            sk=sender_private)
        mac_key = mac_key_box[16:48]
        recipient_mac_keys.append(mac_key)

    # Write the chunks.
    for chunknum, chunk in enumerate(chunks_with_empty(message, chunk_size)):
        payload_nonce = PAYLOAD_NONCE_PREFIX + chunknum.to_bytes(8, "big")
        payload_secretbox = nacl.bindings.crypto_secretbox(
            message=chunk,
            nonce=payload_nonce,
            key=payload_key)
        # Authenticate the hash of the payload for each recipient.
        payload_hash = nacl.bindings.crypto_hash(
            header_hash + payload_nonce + payload_secretbox)
        hash_authenticators = []
        for mac_key in recipient_mac_keys:
            hmac_digest = hmac.new(mac_key, digestmod=hashlib.sha512)
            hmac_digest.update(payload_hash)
            hash_authenticators.append(hmac_digest.digest()[:32])
        packet = [
            hash_authenticators,
            payload_secretbox,
        ]
        output.write(umsgpack.packb(packet))

    return output.getvalue()


def decrypt(input, recipient_private):
    stream = io.BytesIO(input)
    # Parse the header.
    header_bytes = umsgpack.unpack(stream)
    header_hash = nacl.bindings.crypto_hash(header_bytes)
    header = umsgpack.unpackb(header_bytes)
    debug('header:', json_repr(header))
    debug('header hash:', header_hash)
    [
        format_name,
        [major_version, minor_version],
        mode,
        ephemeral_public,
        sender_secretbox,
        recipient_pairs,
        *_,  # ignore additional elements
    ] = header
    ephemeral_beforenm = nacl.bindings.crypto_box_beforenm(
        pk=ephemeral_public,
        sk=recipient_private)

    if format_name != "saltpack":
        raise error.BadFormatError(
            "Unrecognized format name: '{}'".format(format_name))
    if major_version != 1:
        raise error.BadVersionError(
            "Incompatible major version: {}".format(major_version))

    # Try decrypting each sender box, until we find the one that works.
    for recipient_index, pair in enumerate(recipient_pairs):
        [_, payload_key_box, *_] = pair
        try:
            payload_key = nacl.bindings.crypto_box_open_afternm(
                ciphertext=payload_key_box,
                nonce=PAYLOAD_KEY_BOX_NONCE,
                k=ephemeral_beforenm)
            break
        except CryptoError:
            continue
    else:
        raise RuntimeError('Failed to find matching recipient.')

    sender_public = nacl.bindings.crypto_secretbox_open(
        ciphertext=sender_secretbox,
        nonce=SENDER_KEY_SECRETBOX_NONCE,
        key=payload_key)

    mac_key_nonce = header_hash[:24]
    mac_key_box = nacl.bindings.crypto_box(
        message=b'\0'*32,
        nonce=mac_key_nonce,
        pk=sender_public,
        sk=recipient_private)
    mac_key = mac_key_box[16:48]

    debug('recipient index:', recipient_index)
    debug('sender key:', sender_public)
    debug('payload key:', payload_key)
    debug('mac key nonce:', mac_key_nonce)
    debug('mac key:', mac_key)

    # Decrypt each of the packets.
    output = io.BytesIO()
    chunknum = 0
    while True:
        packet = umsgpack.unpack(stream)
        debug('packet:', json_repr(packet))
        [hash_authenticators, payload_secretbox, *_] = packet
        hash_authenticator = hash_authenticators[recipient_index]

        # Verify the secretbox hash.
        payload_nonce = PAYLOAD_NONCE_PREFIX + chunknum.to_bytes(8, "big")
        debug('payload nonce:', payload_nonce)
        payload_hash = nacl.bindings.crypto_hash(
            header_hash + payload_nonce + payload_secretbox)
        debug('hash to authenticate:', payload_hash)
        hmac_digest = hmac.new(mac_key, digestmod=hashlib.sha512)
        hmac_digest.update(payload_hash)
        our_authenticator = hmac_digest.digest()[:32]
        if not hmac.compare_digest(hash_authenticator, our_authenticator):
            raise error.HMACError("HMAC failed to verify.")

        # Open the payload secretbox.
        chunk = nacl.bindings.crypto_secretbox_open(
            ciphertext=payload_secretbox,
            nonce=payload_nonce,
            key=payload_key)
        output.write(chunk)

        debug('chunk:', repr(chunk))

        # The empty chunk signifies the end of the message.
        if chunk == b'':
            break

        chunknum += 1

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
        public = nacl.bindings.crypto_scalarmult_base(private)
        return [public]


def do_encrypt(args):
    message = args['--message']
    visible_recipients = args['--visible']
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
        chunk_size,
        visible_recipients=visible_recipients)
    if not args['--binary']:
        output = (armor.armor(output, message_type="ENCRYPTED MESSAGE") +
                  '\n').encode()
    sys.stdout.buffer.write(output)


def do_decrypt(args):
    message = sys.stdin.buffer.read()
    if not args['--binary']:
        message = armor.dearmor(message.decode())
    private = get_private(args)
    decoded_message = decrypt(message, private)
    sys.stdout.buffer.write(decoded_message)
