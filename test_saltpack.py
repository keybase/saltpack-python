#! /usr/bin/env python3

import binascii
import re
import tempfile
from duct import cmd, sh, BYTES
import pytest

import saltpack

inputstr = """\
Two roads diverged in a yellow wood, and sorry I could not travel both
and be one traveller, long I stood, and looked down one as far as I
could, to where it bent in the undergrowth."""


def test_block():
    blocked = sh('python -m saltpack block', input=inputstr).read()
    print(blocked)
    unblocked = sh('python -m saltpack unblock', input=blocked).read()
    print(unblocked)
    assert inputstr == unblocked


def test_armor():
    encoded = sh('python -m saltpack armor', input=inputstr).read()
    print(encoded)
    decoded = sh('python -m saltpack dearmor', input=encoded).read()
    print(decoded)
    assert inputstr == decoded


def test_armor_raw():
    raw_encoded = sh('python -m saltpack armor --raw', input=inputstr).read()
    print(raw_encoded)
    raw_decoded = sh('python -m saltpack dearmor --raw',
                     input=raw_encoded).read()
    print(raw_decoded)
    assert inputstr == raw_decoded


def test_efficient():
    efficient = sh('python -m saltpack efficient 64').read()
    print(efficient)
    assert re.search('3 bytes.*4 chars', efficient)


message = "foo bar"


def test_encryption():
    encrypted = sh("python -m saltpack encrypt") \
                .read(input=message, stdout=BYTES)
    print(encrypted)
    decrypted = sh("python -m saltpack decrypt --debug").read(input=encrypted)
    assert message == decrypted, repr(message) + " != " + repr(decrypted)


keybase_test_ciphertext = """\
BEGIN KEYBASE SALTPACK ENCRYPTED MESSAGE. kiPgBwdlv6bV9N8 dSkCbjKrku2KOWE
CKyuTXpSz8eiQEL e3MQnnUPheUrja0 Y8Fup2Sq6nJpfDJ DUH4yLqN5VvQAZv 6LiCR5GtOcL0hmT
jmvskQLPoOpAHxJ 9ogsAlwftLw1WV2 aR1SuuiAJuz6EpP U5UQP9glbDpWhdZ jGONhLE7eGgKaVH
yLVe6rNWZ1zSMrD hCiTLJI7R1KwHUA AzK0PWx00xArC3A 1xjMUCWAeHGL6E0 An0sR7CxTFor8yQ
mDfbmMhUKYuFtaU cs51HK5VFmTujND c2u7zCiR99p8MmD QlNIpyzxQjKMF8O KJVouyGur2yAad0
cNbKnEWtEgdHjcZ n3INBILp0h5k1uB 85PzUtZFSdw2JWb twzlH01O5TLQYjl gqlFyLel494wNiq
be9wvgTLriGf87k ArswlMWnoco0ov9 Yo7boufHjV4O6xd IQjmBvKRZ8XbzfP tqUjeYOja6RzNLy
AMnyZ2l9qVGpuzr 00ZebHI7NaHqRxm VCLXjDd8Tu1Xrzy EboJQ6ju0Qqsj1E ELw6WuudzURlLC2
SXrbic8Kw0S1cQI 5v9o02hAitWUxVz vEsHX8ARAmdxF6j QI3rb8frPEX0f0F 7a8O5Ki0vk4uRI1
CGPGOA2gvgAqSi8 JXJylLGG8Ifq7fs X6pQZ3UQMu08auk D2e4dkcox1yQrkV TxdvqHMfyIRe2ya
THLaUOnc3FdC3rN OVBMwQBT16AQBIz 5QGOKSkKqpYeFsI YU1C7sz7zVTvOlx xDsz9YoQ3A4V9NS
9k0qkyTnojnvyws luQvnshKqQrdx5P 6ZYK75PAcn1xyl3 ZbNw4HUIWSDQrKN 5fS5uUiu64Uj2sQ
40GK4IfZwgZAhyT XLcKVjSWvkZ125s zTc0YNcka4wM1ke Thm2Y7dMAzfcmhC OlGs4gQMCxjq0LI
0W3fXOlEkII1Ejp ENaZSMcWlFJm2oi j3xzHMyoI9yIh0a p3xSR3BJ9Gtu9wN kjHNyFsnkP62qhQ
lvl9Kuq53Fj6u8E fc2DLU9rNtrn03H BJ5wvg. END KEYBASE SALTPACK ENCRYPTED MESSAGE.
"""

keybase_test_plaintext = "real keybase message"

keybase_test_secret_key = \
    "f9fc08c9ad53d97859c5fa7e9755e638c5d8942bfc3742b6f27d6147ffdf5389"


def test_decrypt_keybase_message():
    decrypted = cmd("python", "-m", "saltpack", "decrypt",
                    keybase_test_secret_key) \
                .read(input=keybase_test_ciphertext)
    assert decrypted == keybase_test_plaintext


# This is the same ciphertext from above, with a single payload byte changed.
# It should fail to verify the HMAC.
keybase_test_ciphertext_corrupt = """\
BEGIN KEYBASE SALTPACK ENCRYPTED MESSAGE. kiPgBwdlv6bV9N8 dSkCbjKrku2KOWE
CKyuTXpSz8eiQEL e3MQnnUPheUrja0 Y8Fup2Sq6nJpfDJ DUH4yLqN5VvQAZv 6LiCR5GtOcL0hmT
jmvskQLPoOpAHxJ 9ogsAlwftLw1WV2 aR1SuuiAJuz6EpP U5UQP9glbDpWhdZ jGONhLE7eGgKaVH
yLVe6rNWZ1zSMrD hCiTLJI7R1KwHUA AzK0PWx00xArC3A 1xjMUCWAeHGL6E0 An0sR7CxTFor8yQ
mDfbmMhUKYuFtaU cs51HK5VFmTujND c2u7zCiR99p8MmD QlNIpyzxQjKMF8O KJVouyGur2yAad0
cNbKnEWtEgdHjcZ n3INBILp0h5k1uB 85PzUtZFSdw2JWb twzlH01O5TLQYjl gqlFyLel494wNiq
be9wvgTLriGf87k ArswlMWnoco0ov9 Yo7boufHjV4O6xd IQjmBvKRZ8XbzfP tqUjeYOja6RzNLy
AMnyZ2l9qVGpuzr 00ZebHI7NaHqRxm VCLXjDd8Tu1Xrzy EboJQ6ju0Qqsj1E ELw6WuudzURlLC2
SXrbic8Kw0S1cQI 5v9o02hAitWUxVz vEsHX8ARAmdxF6j QI3rb8frPEX0f0F 7a8O5Ki0vk4uRI1
CGPGOA2gvgAqSi8 JXJylLGG8Ifq7fs X6pQZ3UQMu08auk D2e4dkcox1yQrkV TxdvqHMfyIRe2ya
THLaUOnc3FdC3rN OVBMwQBT16AQBIz 5QGOKSkKqpYeFsI YU1C7sz7zVTvOlx xDsz9YoQ3A4V9NS
9k0qkyTnojnvyws luQvnshKqQrdx5P 6ZYK75PAcn1xyl3 ZbNw4RX2rVGI15H BxJi4sZxh2w9GQs
YTJt6IfZwgZAhyT XLcKVjSWvkZ125s zTc0YNcka4wM1ke Thm2Y7dMAzfcmhC OlGs4gQMCxjq0LI
0W3fXOlEkII1Ejp ENaZSMcWlFJm2oi j3xzHMyoI9yIh0a p3xSR3BJ9Gtu9wN kjHNyFsnkP62qhQ
lvl9Kuq53Fj6u8E fc2DLU9rNtrn03H BJ5wvg. END KEYBASE SALTPACK ENCRYPTED MESSAGE.
"""


def test_decrypt_HMAC_failure():
    ciphertext_binary = saltpack.armor.dearmor(keybase_test_ciphertext_corrupt)
    with pytest.raises(saltpack.encrypt.HMACError):
        saltpack.encrypt.decrypt(
            ciphertext_binary,
            binascii.unhexlify(keybase_test_secret_key))


def test_sign_attached():
    signed = sh("python -m saltpack sign").read(input=message)
    print(signed)
    verified = sh("python -m saltpack verify --debug").read(input=signed)
    assert message == verified, repr(message) + " != " + repr(verified)


def test_sign_detached():
    detached = sh("python -m saltpack sign --binary --detached").read(
        input=message, stdout=BYTES)
    print(detached)
    _, temp = tempfile.mkstemp()
    with open(temp, 'wb') as f:
        f.write(detached)
    command = ["python", "-m", "saltpack", "verify", "--signature", temp,
               "--binary", "--debug"]
    cmd(*command).read(input=message)
