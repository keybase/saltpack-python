#! /usr/bin/env python3

import re
from duct import sh

inputstr = """\
Two roads diverged in a yellow wood, and sorry I could not travel both
and be one traveller, long I stood, and looked down one as far as I
could, to where it bent in the undergrowth."""

encoded = sh('./armor.py encode', input=inputstr).read()

print(encoded)

decoded = sh('./armor.py decode', input=encoded).read()

print(decoded)

assert inputstr == decoded

efficient = sh('./armor.py efficient 64').read()

print(efficient)

assert re.search('4 chars.*3 bytes', efficient)
