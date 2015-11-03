#! /usr/bin/env python3

import docopt
import math


__doc__ = '''\
Usage:
    armor.py efficient <alphabet_size>
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


b64alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz123456789+/"


def main():
    args = docopt.docopt(__doc__)
    if args['efficient']:
        alphabet_size = int(args['<alphabet_size>'])
        print_efficient_chars_sizes(alphabet_size, 50)


if __name__ == '__main__':
    main()
