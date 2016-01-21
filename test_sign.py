#! /usr/bin/env python3

import tempfile

from duct import cmd, sh, BYTES

message = "foo bar"

# attached
signed = sh("./sign.py sign").read(input=message)
print(signed)
verified = sh("./sign.py verify --debug").read(input=signed)
assert message == verified, repr(message) + " != " + repr(verified)

# detached
detached = sh("./sign.py sign --binary --detached").read(
    input=message, stdout=BYTES)
print(detached)
_, temp = tempfile.mkstemp()
with open(temp, 'wb') as f:
    f.write(detached)
command = ["./sign.py", "verify", "--signature", temp, "--binary", "--debug"]
cmd(*command).read(input=message)
