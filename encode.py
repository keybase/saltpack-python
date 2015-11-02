#! /usr/bin/env python3

import math


def bytes_per_block(alphabet_size, block_size):
    '''We have to obey the following relationship:
           256 ^ bytes_per_block <= alphabet_size ^ block_size
       Taking the log_2 of both sides solves for bytes_per_block.
    '''
    assert block_size > 1, "encoded blocks must be at least 2 characters"
    return math.floor(math.log(alphabet_size, 2) / 8 * block_size)


def efficient_block_sizes(alphabet_size):
    MAX_BLOCK_SIZE = 100
    out = []
    max_efficiency = 0
    for block_size in range(2, MAX_BLOCK_SIZE):
        bytes_out = bytes_per_block(alphabet_size, block_size)
        efficiency = bytes_out / block_size
        if efficiency > max_efficiency:
            out.append((block_size, bytes_out, efficiency))
            max_efficiency = efficiency
    return out

alpha = 62
print("efficient block sizes for alphabet size", alpha)
for block_size, bytes_out, efficiency in efficient_block_sizes(alpha):
    print("{:2d} chars: {:2d} bytes ({:.2f}%)".format(
        block_size, bytes_out, 100 * efficiency))
