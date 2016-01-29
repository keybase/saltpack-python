#! /usr/bin/env python3

import tempfile

from duct import cmd, sh, BYTES

message = "foo bar"

# attached
signed = sh("python -m saltpack sign").read(input=message)
print(signed)
verified = sh("python -m saltpack verify --debug").read(input=signed)
assert message == verified, repr(message) + " != " + repr(verified)

# detached
detached = sh("python -m saltpack sign --binary --detached").read(
    input=message, stdout=BYTES)
print(detached)
_, temp = tempfile.mkstemp()
with open(temp, 'wb') as f:
    f.write(detached)
command = ["python", "-m", "saltpack", "verify", "--signature", temp,
           "--binary", "--debug"]
cmd(*command).read(input=message)
