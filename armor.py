#! /usr/bin/env python3

import docopt
import math
import sys


__doc__ = '''\
Usage:
    armor.py efficient <alphabet_size> [<max-size>]
    armor.py block [<bytes>] [options]
    armor.py unblock [<chars>] [options]
    armor.py armor [<bytes>] [options]
    armor.py dearmor [<chars>] [options]

Options:
    -a --alphabet=<str>  the alphabet string to index into
    --base64             use the Base64 alphabet and 3-byte blocks
    --base85             use the Base85 alphabet and 4-byte blocks
    -b --block=<size>    the block size
    --shift              shift the encoded number left as far as possible
    --raw                omit 'BEGIN ARMOR.' and 'END ARMOR.'
'''


b64alphabet = \
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

b62alphabet = \
    "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

b85alphabet = \
    "!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ" \
    "[\\]^_`abcdefghijklmnopqrstu"


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


def encode_to_chars(bytes_block, args):
    alphabet = get_alphabet(args)
    # Figure out how wide the chars block needs to be, and how many extra bits
    # we have.
    chars_size = min_chars_size(len(alphabet), len(bytes_block))
    extra = extra_bits(len(alphabet), chars_size, len(bytes_block))
    # Convert the bytes into an integer, big-endian.
    bytes_int = int.from_bytes(bytes_block, byteorder='big')
    # Shift left by the extra bits.
    if args['--shift']:
        bytes_int <<= extra
    # Convert the result into our base.
    places = []
    for place in range(chars_size):
        rem = bytes_int % len(alphabet)
        places.insert(0, rem)
        bytes_int //= len(alphabet)
    return "".join(alphabet[p] for p in places)


def get_char_index(alphabet, char):
    'This is the same as alphabet.index(char), but with more helpful errors.'
    try:
        return alphabet.index(char)
    except ValueError:
        raise ValueError("Could not find {} in alphabet {}.".format(
            repr(char), repr(alphabet)))


def decode_from_chars(chars_block, args):
    alphabet = get_alphabet(args)
    # Figure out how many bytes we have, and how many extra bits they'll have
    # been shifted by.
    bytes_size = max_bytes_size(len(alphabet), len(chars_block))
    extra = extra_bits(len(alphabet), len(chars_block), bytes_size)
    # Convert the chars to an integer.
    bytes_int = get_char_index(alphabet, chars_block[0])
    for c in chars_block[1:]:
        bytes_int *= len(alphabet)
        bytes_int += get_char_index(alphabet, c)
    # Shift right by the extra bits.
    if args['--shift']:
        bytes_int >>= extra
    # Convert the result to bytes, big_endian.
    return bytes_int.to_bytes(bytes_size, byteorder='big')


def chunk_iterable(b, size):
    assert size > 0
    chunks = []
    i = 0
    while i < len(b):
        chunks.append(b[i:i+size])
        i += size
    return chunks


def chunk_string_ignoring_whitespace(s, size):
    'Skip over whitespace when assembling chunks.'
    assert size > 1
    chunks = []
    chunk = ''
    for c in s:
        if c.isspace():
            continue
        chunk += c
        if len(chunk) == size:
            chunks.append(chunk)
            chunk = ''
    if chunk:
        chunks.append(chunk)
    return chunks


def read_between_periods(s):
    start = s.find('.')
    if start == -1:
        raise Exception("No period found in input.")
    end = s.find('.', start+1)
    if end == -1:
        raise Exception("No closing period found in input.")
    return s[start+1:end]


def get_block_size(args):
    block_size = 32
    if args['--block']:
        block_size = int(args['--block'])
    elif args['--base64']:
        block_size = 3
    elif args['--base85']:
        block_size = 4
    return block_size


def get_alphabet(args):
    alphabet = b62alphabet
    if args['--alphabet']:
        alphabet = args['--alphabet']
    elif args['--base64']:
        alphabet = b64alphabet
    elif args['--base85']:
        alphabet = b85alphabet
    return alphabet


def get_bytes_in(args):
    if args['<bytes>'] is not None:
        return args['<bytes>'].encode()
    else:
        return sys.stdin.buffer.read()


def get_chars_in(args):
    if args['<chars>'] is not None:
        return args['<chars>']
    else:
        return sys.stdin.read()


def do_efficient(args):
    if args['<max-size>'] is None:
        upper_bound = 50
    else:
        upper_bound = int(args['<max-size>'])
    alphabet_size = int(args['<alphabet_size>'])
    print_efficient_chars_sizes(alphabet_size, upper_bound)


def do_block(args):
    print(encode_to_chars(get_bytes_in(args), args))


def do_unblock(args):
    chars_in = get_chars_in(args).strip()
    sys.stdout.buffer.write(decode_from_chars(chars_in, args))


def do_armor(args):
    bytes_in = get_bytes_in(args)
    chunks = chunk_iterable(bytes_in, get_block_size(args))
    output = ""
    for chunk in chunks:
        output += encode_to_chars(chunk, args)
    if args['--raw']:
        print(output)
        return
    words = chunk_iterable(output, 15)
    sentences = chunk_iterable(words, 200)
    print('BEGIN ARMOR.')
    print('\n'.join(' '.join(sentence) for sentence in sentences) + '.')
    print('END ARMOR.')


def do_dearmor(args):
    chars_in = get_chars_in(args)
    alphabet = get_alphabet(args)
    char_block_size = min_chars_size(len(alphabet), get_block_size(args))
    if not args['--raw']:
        # Find the substring between the first two periods.
        try:
            first_period = chars_in.index('.')
        except ValueError:
            print("No period found in input.", file=sys.stderr)
            sys.exit(1)
        try:
            second_period = chars_in.index('.', first_period+1)
        except ValueError:
            print("No second period found in input.", file=sys.stderr)
            sys.exit(1)
        chars_in = chars_in[first_period+1:second_period]
    chunks = chunk_string_ignoring_whitespace(chars_in, char_block_size)
    for chunk in chunks:
        sys.stdout.buffer.write(decode_from_chars(chunk, args))


def main():
    args = docopt.docopt(__doc__)

    if args['efficient']:
        do_efficient(args)
    elif args['block']:
        do_block(args)
    elif args['unblock']:
        do_unblock(args)
    elif args['armor']:
        do_armor(args)
    elif args['dearmor']:
        do_dearmor(args)

if __name__ == '__main__':
    main()
