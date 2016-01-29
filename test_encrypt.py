#! /usr/bin/env python3

from duct import sh, BYTES

message = "foo bar"

encrypted = sh("python -m saltpack encrypt").read(input=message, stdout=BYTES)

print(encrypted)

decrypted = sh("python -m saltpack decrypt --debug").read(input=encrypted)

assert message == decrypted, repr(message) + " != " + repr(decrypted)
