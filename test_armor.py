#! /usr/bin/env python3

import re
from duct import sh

inputstr = """\
Two roads diverged in a yellow wood, and sorry I could not travel both
and be one traveller, long I stood, and looked down one as far as I
could, to where it bent in the undergrowth."""

blocked = sh('python -m saltpack block', input=inputstr).read()
print(blocked)
unblocked = sh('python -m saltpack unblock', input=blocked).read()
print(unblocked)
assert inputstr == unblocked

encoded = sh('python -m saltpack armor', input=inputstr).read()
print(encoded)
decoded = sh('python -m saltpack dearmor', input=encoded).read()
print(decoded)
assert inputstr == decoded

raw_encoded = sh('python -m saltpack armor --raw', input=inputstr).read()
print(raw_encoded)
raw_decoded = sh('python -m saltpack dearmor --raw', input=raw_encoded).read()
print(raw_decoded)
assert inputstr == raw_decoded

efficient = sh('python -m saltpack efficient 64').read()
print(efficient)
assert re.search('3 bytes.*4 chars', efficient)
