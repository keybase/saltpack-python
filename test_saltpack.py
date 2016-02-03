#! /usr/bin/env python3

import re
import tempfile
from duct import cmd, sh, BYTES

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
