#! /usr/bin/env python3

import io
import math
import os
import sys


b64alphabet = \
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

b62alphabet = \
    "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

b85alphabet = \
    "!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ" \
    "[\\]^_`abcdefghijklmnopqrstu"

here = os.path.dirname(__file__)
props_file = os.path.join(here, 'unicode/DerivedNormalizationProps.txt')
categories_file = os.path.join(here, 'unicode/UnicodeData.txt')


def parse_non_quick_check():
    '''The file DerivedNormalizationProps.txt defines all the code points with
    NFC_Quick_Check values of No or Maybe. Parse these out, so that we can
    exclude them from the Twitter alphabet.'''
    bad_code_points = set()
    with open(props_file) as f:
        for line in f:
            # Strip comments.
            comment_start = line.find('#')
            if comment_start != -1:
                line = line[:comment_start]
            # Skip unrealted lines.
            if 'NFC_QC' not in line:
                continue
            # Parse out the code point or range of code points.
            hex_points = line.split(';')[0].strip().split('..')
            points = [int(point, 16) for point in hex_points]
            # Add single code points, or every code point in the given range
            # (inclusive).
            if len(points) == 1:
                bad_code_points.add(points[0])
            else:
                for i in range(points[0], points[1]+1):
                    bad_code_points.add(i)
    return bad_code_points


bad_unicode_categories = {
    "Cc",  # control characters
    "Cf",  # format characters
    "Cs",  # surrogate characters
    "Zl",  # line separators
    "Zp",  # paragraph separators
    "Zs",  # space separators
}


def parse_bad_unicode_categories():
    '''The file UnicodeData.txt gives the category for every defined Unicode
    character, according to Unicode version 8.0.0. We use this checked-in file
    instead of unicodedata.category(), because that function uses an older
    version of the Unicode standard in older Python versions.'''
    bad_code_points = set()
    with open(categories_file) as f:
        for line in f:
            code_str, name, category = line.split(';')[:3]
            if category not in bad_unicode_categories:
                continue
            code = int(code_str, 16)
            # Some lines represent ranges.
            if name.endswith(", First>"):
                last_code_str = next(f).split(';')[0]
                last_code = int(last_code_str, 16)
                for i in range(code, last_code+1):
                    bad_code_points.add(i)
            else:
                bad_code_points.add(code)
    return bad_code_points


def get_twitter_alphabet():
    '''We want to use every possible code point we can. That means starting at
    0 and going all the way up to 0x10ffff, the largest encodable value.
    Because Twitter does NFC Unicode normalization, we need to omit characters
    that don't have the NFC_Quick_Check=Yes property. We also need to omit
    characters that Twitter might strip, as well as the surrogate characters,
    which aren't legal to encode.'''
    non_quick_check_code_points = parse_non_quick_check()
    bad_category_code_points = parse_bad_unicode_categories()
    buffer = io.StringIO()
    for i in range(0x110000):
        if i in non_quick_check_code_points:
            continue
        if i in bad_category_code_points:
            continue
        c = chr(i)
        buffer.write(c)
    return buffer.getvalue()


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
        print("{:2d} bytes: {:2d} chars ({:.2f}%)".format(
            bytes_size, chars_size, 100 * efficiency))


def extra_bits(alphabet_size, chars_size, bytes_size):
    '''In order to be compatible with Base64, when we write a partial block, we
    need to shift as far left as we can. Figure out how many whole extra bits
    the encoding space has relative to the bytes coming in.'''
    total_bits = math.floor(math.log(alphabet_size, 2) * chars_size)
    return total_bits - 8*bytes_size


def encode_block(bytes_block, alphabet, *, shift=False):
    # Figure out how wide the chars block needs to be, and how many extra bits
    # we have.
    chars_size = min_chars_size(len(alphabet), len(bytes_block))
    extra = extra_bits(len(alphabet), chars_size, len(bytes_block))
    # Convert the bytes into an integer, big-endian.
    bytes_int = int.from_bytes(bytes_block, byteorder='big')
    # Shift left by the extra bits.
    if shift:
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


def decode_block(chars_block, alphabet, *, shift=False):
    # Figure out how many bytes we have, and how many extra bits they'll have
    # been shifted by.
    bytes_size = max_bytes_size(len(alphabet), len(chars_block))
    expected_char_size = min_chars_size(len(alphabet), bytes_size)
    assert len(chars_block) == expected_char_size, \
        "illegal chars size {}, expected {}".format(
            len(chars_block), expected_char_size)
    extra = extra_bits(len(alphabet), len(chars_block), bytes_size)
    # Convert the chars to an integer.
    bytes_int = get_char_index(alphabet, chars_block[0])
    for c in chars_block[1:]:
        bytes_int *= len(alphabet)
        bytes_int += get_char_index(alphabet, c)
    # Shift right by the extra bits.
    if shift:
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
    # This is a very forgiving parser. It doesn't enforce that the message
    # starts with "BEGIN..." or ends with "END...". We should make this
    # stricter eventually.
    start = s.find('.')
    if start == -1:
        raise Exception("No period found in input.")
    end = s.find('.', start+1)
    if end == -1:
        raise Exception("No closing period found in input.")
    return s[start+1:end]


def armor(input_bytes, *, alphabet=b62alphabet, block_size=32, raw=False,
          shift=False, message_type='MESSAGE'):
    chunks = chunk_iterable(input_bytes, block_size)
    output = ""
    for chunk in chunks:
        output += encode_block(chunk, alphabet, shift=shift)
    if raw:
        return ' '.join(chunk_iterable(output, 43))
    words = chunk_iterable(output, 15)
    sentences = chunk_iterable(words, 200)
    joined = '\n'.join(' '.join(sentence) for sentence in sentences)
    header = 'BEGIN SALTPACK {}. '.format(message_type)
    footer = '. END SALTPACK {}.'.format(message_type)
    return header + joined + footer


def dearmor(input_chars, *, alphabet=b62alphabet, char_block_size=43,
            raw=False, shift=False):
    if not raw:
        # Find the substring between the first two periods.
        try:
            first_period = input_chars.index('.')
        except ValueError:
            print("No period found in input.", file=sys.stderr)
            sys.exit(1)
        try:
            second_period = input_chars.index('.', first_period+1)
        except ValueError:
            print("No second period found in input.", file=sys.stderr)
            sys.exit(1)
        input_chars = input_chars[first_period+1:second_period]
    chunks = chunk_string_ignoring_whitespace(input_chars, char_block_size)
    output = b''
    for chunk in chunks:
        output += decode_block(chunk, alphabet, shift=shift)
    return output


def get_block_size(args):
    block_size = 32
    if args['--block']:
        block_size = int(args['--block'])
    elif args['--base64']:
        block_size = 3
    elif args['--base85']:
        block_size = 4
    elif args['--twitter']:
        block_size = 351
    return block_size


def get_alphabet(args):
    alphabet = b62alphabet
    if args['--alphabet']:
        alphabet = args['--alphabet']
    elif args['--base64']:
        alphabet = b64alphabet
    elif args['--base85']:
        alphabet = b85alphabet
    elif args['--twitter']:
        alphabet = get_twitter_alphabet()
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
    alphabet = get_alphabet(args)
    bytes_input = get_bytes_in(args)
    shift = args['--shift']
    print(encode_block(bytes_input, alphabet, shift=shift))


def do_unblock(args):
    alphabet = get_alphabet(args)
    chars_in = get_chars_in(args).strip()
    shift = args['--shift']
    sys.stdout.buffer.write(decode_block(chars_in, alphabet, shift=shift))


def do_armor(args):
    alphabet = get_alphabet(args)
    bytes_in = get_bytes_in(args)
    shift = args['--shift']
    raw = args['--raw']
    block_size = get_block_size(args)
    armored = armor(bytes_in, alphabet=alphabet, block_size=block_size,
                    raw=raw, shift=shift)
    print(armored)


def do_dearmor(args):
    chars_in = get_chars_in(args)
    alphabet = get_alphabet(args)
    shift = args['--shift']
    raw = args['--raw']
    char_block_size = min_chars_size(len(alphabet), get_block_size(args))
    dearmored = dearmor(chars_in, alphabet=alphabet,
                        char_block_size=char_block_size, raw=raw, shift=shift)
    sys.stdout.buffer.write(dearmored)
