#! /usr/bin/env python3

import docopt
import math
import sys


__doc__ = '''\
Usage:
    armor.py efficient <alphabet_size>
    armor.py encode [<bytes>] [--alphabet=<chars>]
    armor.py decode [<chars>] [--alphabet=<chars>]
'''


def min_chars_size(alphabet_size, bytes_size):
    '''The most bytes we can represent satisfies this:
           256 ^ bytes_size <= alphabet_size ^ chars_size
       Take the log_2 of both sides:
           8 * bytes_size <= log_2(alphabet_size) * chars_size
        Solve for the minimum chars_size:
    '''
    return math.ceil(8 * bytes_size / math.log(alphabet_size, 2))


def max_bytes_size(alphabet_size, chars_size):
    '''The most bytes we can represent satisfies this:
           256 ^ bytes_size <= alphabet_size ^ chars_size
       Take the log_2 of both sides:
           8 * bytes_size <= log_2(alphabet_size) * chars_size
        Solve for the maximum bytes_size:
    '''
    return math.floor(math.log(alphabet_size, 2) / 8 * chars_size)


def efficient_chars_sizes(alphabet_size, chars_size_upper_bound):
    out = []
    max_efficiency = 0
    for chars_size in range(1, chars_size_upper_bound):
        bytes_size = max_bytes_size(alphabet_size, chars_size)
        efficiency = bytes_size / chars_size
        # This check also excludes sizes too small to encode a single byte.
        if efficiency > max_efficiency:
            out.append((chars_size, bytes_size, efficiency))
            max_efficiency = efficiency
    return out


def print_efficient_chars_sizes(alphabet_size, chars_size_upper_bound):
    print("efficient block sizes for alphabet size", alphabet_size)
    for chars_size, bytes_size, efficiency in \
            efficient_chars_sizes(alphabet_size, chars_size_upper_bound):
        print("{:2d} chars: {:2d} bytes ({:.2f}%)".format(
            chars_size, bytes_size, 100 * efficiency))


def extra_bits(alphabet_size, chars_size, bytes_size):
    '''In order to be compatible with Base64, when we write a partial block, we
    need to shift as far left as we can. Figure out how many whole extra bits
    the encoding space has relative to the bytes coming in.'''
    total_bits = math.floor(math.log(alphabet_size, 2) * chars_size)
    return total_bits - 8*bytes_size


def encode_to_chars(alphabet, bytes_block):
    # Figure out how wide the chars block needs to be, and how many extra bits
    # we have.
    chars_size = min_chars_size(len(alphabet), len(bytes_block))
    extra = extra_bits(len(alphabet), chars_size, len(bytes_block))
    # Convert the bytes into an integer, big-endian.
    bytes_int = int.from_bytes(bytes_block, byteorder='big')
    # Shift left by the extra bits.
    bytes_int <<= extra
    # Convert the result into our base.
    places = []
    for place in range(chars_size):
        rem = bytes_int % len(alphabet)
        places.insert(0, rem)
        bytes_int //= len(alphabet)
    return "".join(alphabet[p] for p in places)


def decode_from_chars(alphabet, chars_block):
    # Figure out how many bytes we have, and how many extra bits they'll have
    # been shifted by.
    bytes_size = max_bytes_size(len(alphabet), len(chars_block))
    extra = extra_bits(len(alphabet), len(chars_block), bytes_size)
    # Convert the chars to an integer.
    bytes_int = alphabet.index(chars_block[0])
    for c in chars_block[1:]:
        bytes_int *= len(alphabet)
        bytes_int += alphabet.index(c)
    # Shift right by the extra bits.
    bytes_int >>= extra
    # Convert the result to bytes, big_endian.
    return bytes_int.to_bytes(bytes_size, byteorder='big')


b64alphabet = \
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def main():
    args = docopt.docopt(__doc__)
    if args['--alphabet'] is not None:
        alphabet = args['--alphabet']
    else:
        alphabet = b64alphabet

    if args['efficient']:
        alphabet_size = int(args['<alphabet_size>'])
        print_efficient_chars_sizes(alphabet_size, 50)
    elif args['encode']:
        if args['<bytes>'] is not None:
            bytes_in = args['<bytes>'].encode()
        else:
            bytes_in = sys.stdin.buffer.read()
        print(encode_to_chars(alphabet, bytes_in))
    elif args['decode']:
        if args['<chars>'] is not None:
            chars_in = args['<chars>']
        else:
            chars_in = sys.stdin.read()
        print(decode_from_chars(alphabet, chars_in))


if __name__ == '__main__':
    main()
