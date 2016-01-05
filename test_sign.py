#! /usr/bin/env python3

import tempfile

from duct import cmd, sh

message = "foo bar"

# attached
signed = sh("./sign.py sign --armor").read(input=message)
print(signed)
verified = sh("./sign.py verify --armor --debug").read(input=signed)
assert message == verified, repr(message) + " != " + repr(verified)

# detached
detached = sh("./sign.py sign --armor --detached").read(input=message)
print(detached)
_, temp = tempfile.mkstemp()
with open(temp, 'w') as f:
    f.write(detached)
command = ["./sign.py", "verify", "--signature", temp, "--armor", "--debug"]
cmd(*command).read(input=message)
