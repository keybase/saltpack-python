#! /usr/bin/env python3

import re
from duct import sh

inputstr = """\
Two roads diverged in a yellow wood, and sorry I could not travel both
and be one traveller, long I stood, and looked down one as far as I
could, to where it bent in the undergrowth."""

blocked = sh('./armor.py block', input=inputstr).read()
print(blocked)
unblocked = sh('./armor.py unblock', input=blocked).read()
print(unblocked)
assert inputstr == unblocked

encoded = sh('./armor.py armor', input=inputstr).read()
print(encoded)
decoded = sh('./armor.py dearmor', input=encoded).read()
print(decoded)
assert inputstr == decoded

raw_encoded = sh('./armor.py armor --raw', input=inputstr).read()
print(raw_encoded)
raw_decoded = sh('./armor.py dearmor --raw', input=raw_encoded).read()
print(raw_decoded)
assert inputstr == raw_decoded

efficient = sh('./armor.py efficient 64').read()
print(efficient)
assert re.search('4 chars.*3 bytes', efficient)
