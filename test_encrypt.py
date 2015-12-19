#! /usr/bin/env python3

from duct import sh, BYTES

message = "foo bar"

encrypted = sh("./encrypt.py encrypt").read(input=message, stdout=BYTES)

print(encrypted)

decrypted = sh("./encrypt.py decrypt --debug").read(input=encrypted)

assert message == decrypted, repr(message) + " != " + repr(decrypted)
