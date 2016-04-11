from . import encrypt, sign, armor, error

from os import path

with open(path.join(path.dirname(__file__), "VERSION")) as f:
    __version__ = f.read().strip()
