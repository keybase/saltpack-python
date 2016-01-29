import binascii
import sys

DEBUG_MODE = False


def tohex(b):
    return binascii.hexlify(b).decode()


def debug(*args):
    # hexify any bytes values
    args = list(args)
    for i, arg in enumerate(args):
        if isinstance(arg, bytes):
            args[i] = tohex(args[i])
    # print to stderr, if we're in debug mode
    if DEBUG_MODE:
        print(*args, file=sys.stderr)
