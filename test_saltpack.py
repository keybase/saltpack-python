#! /usr/bin/env python3

import binascii
import re
import tempfile
from duct import cmd, sh
import pytest

import saltpack

inputstr = """\
Two roads diverged in a yellow wood, and sorry I could not travel both
and be one traveller, long I stood, and looked down one as far as I
could, to where it bent in the undergrowth."""


def test_block():
    blocked = sh('python -m saltpack block').input(inputstr).read()
    print(blocked)
    unblocked = sh('python -m saltpack unblock').input(blocked).read()
    print(unblocked)
    assert inputstr == unblocked


def test_armor():
    encoded = sh('python -m saltpack armor').input(inputstr).read()
    print(encoded)
    decoded = sh('python -m saltpack dearmor').input(encoded).read()
    print(decoded)
    assert inputstr == decoded


def test_armor_raw():
    raw_encoded = sh('python -m saltpack armor --raw').input(inputstr).read()
    print(raw_encoded)
    raw_decoded = sh('python -m saltpack dearmor --raw') \
        .input(raw_encoded) \
        .read()
    print(raw_decoded)
    assert inputstr == raw_decoded


def test_efficient():
    efficient = sh('python -m saltpack efficient 64').read()
    print(efficient)
    assert re.search('3 bytes.*4 chars', efficient)


message = "foo bar"


def test_encryption():
    encrypted = sh("python -m saltpack encrypt") \
        .input(message) \
        .read()
    print(encrypted)
    decrypted = sh("python -m saltpack decrypt --debug") \
        .input(encrypted) \
        .read()
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
        .input(keybase_test_ciphertext) \
        .read()
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
    with pytest.raises(saltpack.error.HMACError):
        saltpack.encrypt.decrypt(
            ciphertext_binary,
            binascii.unhexlify(keybase_test_secret_key))


bad_format_message = (
    #    badness here ↓
    b'\xc4\x97\x96\xa8XXXXpack\x92\x01\x00\x00\xc4 \xf6\xa9\x9e\xe2\xac7\x8c.B'
    b'o\x02-\x8b}^\xf0\x90\xee4_C\xeb\xc9\x842\x1fe\xbf\xd8\x18\x0bb\xc402\xe9'
    b'\xc6c\xcf;=;\xfd\x17\xc5\xc1\x04"\xa7\xc9\xe9\xb0*\xc2\xbfa\xa0<\xc4 T'
    b'\x7f\xc4-z\x8d\xa4\x07\xd6\xa1\xa1\xecP\xf5\x1b\n\xc2\xdc\x952\xf09\x91'
    b'\x92\xc0\xc40\xd0\xf3\xdcM[\x94\xb0F\xa0l\x109\xd64\xd6\x89\x7f\x12.\x13'
    b'/C\x83\xd6\xba\xbaQ\xf1W\x990\x94\x83\x10fh\x9c\xa8$]\x7fn\x93*\x99\x83'
    b'\xe4\x0e\x92\x91\xc4 y\xe1*\xbda\x9bE\x85+7\xfd\xfasE\xf6\xaa\x9f\x97o'
    b'\xa4\xfeB\xf5r\xcb\x01\x8a\xd9\xa5d\xbc\xa6\xc4\x10:\x0b\x8f\xbf\xfa>#'
    b'\xaa\xe3ax\xfb\xd2?M\x9c'
)


def test_decrypt_bad_format():
    with pytest.raises(saltpack.error.BadFormatError):
        saltpack.encrypt.decrypt(bad_format_message, b'\0'*32)


bad_version_message = (
    #                  badness here ↓
    b'\xc4\x97\x96\xa8saltpack\x92\xff\x00\x00\xc4 \xf6\xa9\x9e\xe2\xac7\x8c.B'
    b'o\x02-\x8b}^\xf0\x90\xee4_C\xeb\xc9\x842\x1fe\xbf\xd8\x18\x0bb\xc402\xe9'
    b'\xc6c\xcf;=;\xfd\x17\xc5\xc1\x04"\xa7\xc9\xe9\xb0*\xc2\xbfa\xa0<\xc4 T'
    b'\x7f\xc4-z\x8d\xa4\x07\xd6\xa1\xa1\xecP\xf5\x1b\n\xc2\xdc\x952\xf09\x91'
    b'\x92\xc0\xc40\xd0\xf3\xdcM[\x94\xb0F\xa0l\x109\xd64\xd6\x89\x7f\x12.\x13'
    b'/C\x83\xd6\xba\xbaQ\xf1W\x990\x94\x83\x10fh\x9c\xa8$]\x7fn\x93*\x99\x83'
    b'\xe4\x0e\x92\x91\xc4 y\xe1*\xbda\x9bE\x85+7\xfd\xfasE\xf6\xaa\x9f\x97o'
    b'\xa4\xfeB\xf5r\xcb\x01\x8a\xd9\xa5d\xbc\xa6\xc4\x10:\x0b\x8f\xbf\xfa>#'
    b'\xaa\xe3ax\xfb\xd2?M\x9c'
)


def test_decrypt_bad_version():
    with pytest.raises(saltpack.error.BadVersionError):
        saltpack.encrypt.decrypt(bad_version_message, b'\0'*32)


def test_sign_attached():
    signed = sh("python -m saltpack sign").input(message).read()
    print(signed)
    verified = sh("python -m saltpack verify --debug").input(signed).read()
    assert message == verified, repr(message) + " != " + repr(verified)


def test_sign_detached():
    detached = sh("python -m saltpack sign --binary --detached") \
            .input(message) \
            .stdout_capture() \
            .run() \
            .stdout
    print(detached)
    _, temp = tempfile.mkstemp()
    with open(temp, 'wb') as f:
        f.write(detached)
    command = ["python", "-m", "saltpack", "verify", "--signature", temp,
               "--binary", "--debug"]
    cmd(*command).input(message).read()


LOREM_IPSUM_FIRST_351 = ' '.join('''\
Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor
incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis
nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat.
Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu
fugiat nulla pariatur. Excepteur sint o'''.split('\n')).encode()


LOREM_IPSUM_TWEET = b'''\
\xe6\xad\xa8\xf2\x93\x80\xaf\xf3\xbf\x82\x9e\xe5\xab\x93\xf4\x85\xa7\xaf\xf3\
\x98\xbf\x8f\xf2\xb4\xbe\xa7\xf1\x90\xab\xb2\xf0\xa3\xb5\xb4\xf2\xb1\x92\xba\
\xf1\xa0\x8e\x9c\xf0\xb3\x8e\x98\xf4\x81\x98\x8b\xf1\xb7\xa6\x8d\xf0\xbe\xa8\
\xb8\xf0\xa1\xb9\x8c\xf0\xbe\xa3\xa5\xf3\x9e\x91\x90\xf0\xa2\x9b\xa2\xf1\xac\
\xb0\x80\xf1\x88\xab\xb3\xf1\x87\x8e\xae\xf1\xa0\x9c\xb2\xf1\xb5\xbb\x89\xf1\
\xa9\xb7\xb2\xf1\xaf\xaf\xa3\xf4\x83\xb2\x8d\xf2\xbd\x9a\xa9\xf0\x9c\x9f\x91\
\xf2\xb9\xa1\xb5\xf1\x8a\xb6\xb9\xf1\x9f\x83\x9b\xf3\xa1\xb0\xbc\xf1\xa3\x80\
\xb7\xf0\xad\xa0\xaa\xec\x9d\x9c\xf2\x9d\xbf\x82\xf0\x96\x9c\xa9\xe8\xbd\x80\
\xf0\xa0\xbb\xb4\xf2\xb4\xb2\xb8\xf1\x96\xa3\xab\xf3\xb1\xb6\x92\xf4\x88\xa6\
\x96\xf2\x85\x9e\xa1\xf1\x92\x8a\x96\xf2\x88\xa9\xac\xf1\xb5\x9f\x9e\xf2\x91\
\x94\xa4\xf3\xb8\xbb\x83\xf3\xb3\xb6\xb7\xf0\xb9\x8c\x9e\xf0\xb5\x8d\xae\xf1\
\xa4\xa4\xb4\xf1\xb8\xb5\x8c\xf0\x9a\xae\x90\xf3\x9b\xa8\xac\xf4\x8d\x92\xa2\
\xf0\xb9\xb7\xb8\xf2\x9c\xa0\xa5\xf0\x94\x8f\x95\xf1\x8c\x9b\x92\xf1\xbd\x92\
\x87\xf1\x84\xad\x9e\xf2\x99\xba\xb6\xf0\x96\x80\xa9\xf3\x90\x8e\x90\xf1\x82\
\xb2\xb7\xf0\xae\xa6\x83\xf3\x94\xa3\xb4\xf0\x9b\x8c\x8d\xf1\x94\xad\x98\xf4\
\x82\x94\xa8\xe5\x82\xbe\xf1\xb2\xb6\xa2\xf0\xbc\xa7\x8b\xf3\xa8\xad\xbd\xf2\
\x95\x93\x94\xf3\x96\xb5\x9b\xf3\xad\x9a\x98\xf3\xb0\x8f\xba\xf3\x95\xb1\x91\
\xf1\x81\x95\x8c\xf3\x82\xa1\x92\xf3\xab\x84\x88\xf0\x9e\xb1\xa2\xf0\x92\x82\
\xbe\xf0\xb3\xb6\xb2\xf4\x81\xb3\x91\xf1\xbd\x84\x8b\xf1\x94\xaa\xab\xf1\xb5\
\xba\x8e\xf0\xb0\xa0\x98\xf1\x95\x88\x93\xf4\x86\x97\x9f\xf1\x81\xb5\xaa\xf2\
\xaa\xad\x90\xf1\xba\xac\xb0\xf3\x91\xba\xad\xf0\xa7\x88\x87\xf2\x81\x8b\x97\
\xf0\x94\x95\xb6\xf0\xb0\x8c\xba\xf3\xa3\xba\x97\xf1\xb5\xba\x9e\xf0\x93\x8b\
\xb7\xf2\xb1\xac\xb1\xf0\x9b\xa8\xa5\xf0\xbb\x92\x8b\xf3\x96\xa6\x92\xf4\x8c\
\x90\x9a\xf2\xaa\xac\xa2\xf2\x9c\x86\x9a\xf3\x81\x89\x86\xf0\x97\xb2\x99\xf2\
\x9f\x83\x8b\xf3\xb6\xb0\xb4\xf2\x8b\xae\x80\xf1\x84\xa8\x9c\xf1\x9a\xa6\xbf\
\xf1\x83\xa4\xad\xf3\xb9\xb4\x90\xf2\x94\x86\xad\xf2\x9e\xbb\x92\xf2\xb0\x81\
\x96\xf1\xa2\x82\x8e\xf2\x9d\xa8\x91\xf1\x89\xbe\xbe\xf3\xa8\x9b\xae\xf3\x98\
\x81\xa8\xf3\x99\xbf\xa2\xf2\xb9\xa4\x8a\xf0\x9e\x83\x86\xf3\x89\x96\x94\xf0\
\x9c\xbd\x8b\xf2\xb9\x82\x82\xf3\xaa\x9d\x9a\xf2\xbd\xb5\x9a\xf3\xa1\x8c\x8d\
\xf3\x8d\x85\x9a'''.decode()


# This takes a little while. Do it once.
TWITTER_ALPHABET = saltpack.armor.get_twitter_alphabet()


def test_encode_twitter():
    encoded = saltpack.armor.encode_block(
        LOREM_IPSUM_FIRST_351, TWITTER_ALPHABET)
    assert encoded == LOREM_IPSUM_TWEET


def test_decode_twitter():
    decoded = saltpack.armor.decode_block(LOREM_IPSUM_TWEET, TWITTER_ALPHABET)
    assert decoded == LOREM_IPSUM_FIRST_351
