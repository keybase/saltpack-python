#! /usr/bin/env python3

import docopt
import math


__doc__ = '''\
Usage:
    armor.py efficient <alphabet_size>
'''


def bytes_per_block(alphabet_size, block_size):
    '''We have to obey the following relationship:
           256 ^ bytes_per_block <= alphabet_size ^ block_size
       Taking the log_2 of both sides solves for bytes_per_block.
    '''
    return math.floor(math.log(alphabet_size, 2) / 8 * block_size)


def efficient_block_sizes(alphabet_size, max_block_size):
    out = []
    max_efficiency = 0
    for block_size in range(1, max_block_size):
        bytes_out = bytes_per_block(alphabet_size, block_size)
        efficiency = bytes_out / block_size
        # This check also excludes sizes too small to encode a single byte.
        if efficiency > max_efficiency:
            out.append((block_size, bytes_out, efficiency))
            max_efficiency = efficiency
    return out


def print_efficient_block_sizes(alphabet_size, max_block_size):
    print("efficient block sizes for alphabet size", alphabet_size)
    for block_size, bytes_out, efficiency in \
            efficient_block_sizes(alphabet_size, max_block_size):
        print("{:2d} chars: {:2d} bytes ({:.2f}%)".format(
            block_size, bytes_out, 100 * efficiency))


def main():
    args = docopt.docopt(__doc__)
    if args['efficient']:
        alphabet_size = int(args['<alphabet_size>'])
        print_efficient_block_sizes(alphabet_size, 50)


if __name__ == '__main__':
    main()
