#!/usr/bin/python
"""
Implements decoding for Windows Script Encoder.

Reference:
https://web.archive.org/web/20131208110057/http://virtualconspiracy.com/content/articles/breaking-screnc

Referenced in writing:
https://gist.github.com/bcse/1834878
"""
import base64
import struct


def decode(inputBuf, outputBuf):
    """
    Reads from inputBuf, decodes, and writes to outputBuf.

    Returns 1 if checksum fails and 0 if successful
    """
    # Checksum for running total
    chksum  = 0
    # "Header"
    header  = inputBuf.read(4)
    b64_len = inputBuf.read(8)
    d64_len = base64.b64decode(b64_len)
    enc_len = struct.unpack('<I', d64_len)[0]


    for i in range(enc_len):
        c = inputBuf.read(1)

        if c == '@':
            c = inputBuf.read(1)
            c = ESCAPE_CHARS[c]
        else:
            c = chr(DECODING_TABLE[c][PICK_ENCODING[i%64]])

        chksum += 1
        outputBuf.write(c)

    b64_chk = inputBuf.read(8)
    d64_chk = base64.b64decode(b64_len)
    wrt_sum = struct.unpack('<I', d64_chk)[0] 

    if chksum != wrt_sum:
        return 1

    return 0


def main():
    import argparse
    import logging
    import sys

    parser = argparse.ArgumentParser(
        description='Decodes scripts encoded by Windows Script Editor'
    )
    parser.add_argument(
        "-i", 
        "--input", 
        help='Input file. Pipe in for stdin, or specify it with "-"'
    )
    parser.add_argument(
        "-o",
        "--output", 
        help='Output. Writes to stdout by default'
    )

    args = parser.parse_args()

    if not args.input and sys.stdin.isatty():
        logging.error('No pipe detected. Force reading from stdin with "-"')
        return
    elif not args.input or args.input == '-':
        inputBuf = sys.stdin
    else:
        try:
            inputBuf = open(args.input)
        except OSError as e:
            logging.error(
                "Error({}) opening {}: {}".format(
                    e.errno,
                    e.filename,
                    e.strerror
                )
            )
            return

    if not args.output or args.input == '-':
        outputBuf = sys.stdout
    else:
        try:
            outputBuf = open(args.output, 'x')
        except OSError as e:
            logging.error(
                "Error({}) opening {}: {}".format(
                    e.errno,
                    e.filename,
                    e.strerror
                )
            )
            try:
                inputBuf.close()
            except:
                pass

            return

    r = decode(inputBuf, outputBuf)
    if r:
        logging.warn("Checksum failed")

    return
        

PICK_ENCODING = (1, 2, 0, 1, 2, 0, 2, 0,
                 0, 2, 0, 2, 1, 0, 2, 0, 
                 1, 0, 2, 0, 1, 1, 2, 0,
                 0, 2, 1, 0, 2, 0, 0, 2, 
                 1, 1, 0, 2, 0, 2, 0, 1, 
                 0, 1, 1, 2, 0, 1, 0, 2, 
                 1, 0, 2, 0, 1, 1, 2, 0, 
                 0, 1, 1, 2, 0, 1, 0, 2
                )

ESCAPE_CHARS = {"#": "\r",
                "&": "\n",
                "!": "<",
                "*": ">",
                "$": "@",
               }

DECODING_TABLE = {
    '\t'  : (0x7b, 0x57, 0x6e), ' '   : (0x32, 0x2e, 0x2d),
    '!'   : (0x30, 0x47, 0x75), '"'   : (0x21, 0x7a, 0x52),
    '#'   : (0x29, 0x56, 0x60), '$'   : (0x5b, 0x42, 0x71),
    '%'   : (0x38, 0x6a, 0x5e), '&'   : (0x33, 0x2f, 0x49),
    "'"   : (0x3d, 0x26, 0x5c), '('   : (0x58, 0x49, 0x62),
    ')'   : (0x3a, 0x41, 0x7d), '*'   : (0x35, 0x34, 0x29),
    '+'   : (0x65, 0x32, 0x36), ','   : (0x39, 0x5b, 0x20),
    '-'   : (0x5c, 0x76, 0x7c), '.'   : (0x56, 0x72, 0x7a),
    '/'   : (0x73, 0x43, 0x00), '0'   : (0x66, 0x38, 0x6b),
    '1'   : (0x4e, 0x39, 0x63), '2'   : (0x45, 0x70, 0x33),
    '3'   : (0x6b, 0x45, 0x2b), '4'   : (0x62, 0x68, 0x68),
    '5'   : (0x59, 0x71, 0x51), '6'   : (0x78, 0x4f, 0x66),
    '7'   : (0x5e, 0x09, 0x76), '8'   : (0x7d, 0x62, 0x31),
    '9'   : (0x4a, 0x44, 0x64), ':'   : (0x6d, 0x23, 0x54),
    ';'   : (0x71, 0x75, 0x43), '='   : (0x60, 0x7e, 0x3a),
    '?'   : (0x53, 0x5e, 0x7e), 'A'   : (0x42, 0x77, 0x45),
    'B'   : (0x27, 0x4a, 0x2c), 'C'   : (0x48, 0x61, 0x2a),
    'D'   : (0x72, 0x5d, 0x74), 'E'   : (0x75, 0x22, 0x27),
    'F'   : (0x31, 0x4b, 0x37), 'G'   : (0x37, 0x6f, 0x44),
    'H'   : (0x4d, 0x4e, 0x79), 'I'   : (0x52, 0x3b, 0x59),
    'J'   : (0x22, 0x4c, 0x2f), 'K'   : (0x54, 0x50, 0x6f),
    'L'   : (0x6a, 0x67, 0x26), 'M'   : (0x47, 0x2a, 0x72),
    'N'   : (0x64, 0x7d, 0x6a), 'O'   : (0x2d, 0x74, 0x39),
    'P'   : (0x20, 0x54, 0x7b), 'Q'   : (0x00, 0x2b, 0x3f),
    'R'   : (0x2e, 0x2d, 0x38), 'S'   : (0x4c, 0x2c, 0x77),
    'T'   : (0x5d, 0x30, 0x67), 'U'   : (0x7e, 0x6e, 0x53),
    'V'   : (0x6c, 0x6b, 0x47), 'W'   : (0x6f, 0x66, 0x34),
    'X'   : (0x79, 0x35, 0x78), 'Y'   : (0x74, 0x25, 0x5d),
    'Z'   : (0x43, 0x21, 0x30), '['   : (0x26, 0x64, 0x23),
    '\\'  : (0x76, 0x4d, 0x5a), ']'   : (0x25, 0x52, 0x5b),
    '^'   : (0x24, 0x63, 0x6c), '_'   : (0x2b, 0x3f, 0x48),
    '`'   : (0x28, 0x7b, 0x55), 'a'   : (0x23, 0x78, 0x70),
    'b'   : (0x41, 0x29, 0x69), 'c'   : (0x34, 0x28, 0x2e),
    'd'   : (0x09, 0x73, 0x4c), 'e'   : (0x2a, 0x59, 0x21),
    'f'   : (0x44, 0x33, 0x24), 'g'   : (0x3f, 0x00, 0x4e),
    'h'   : (0x77, 0x6d, 0x50), 'i'   : (0x3b, 0x55, 0x09),
    'j'   : (0x55, 0x53, 0x56), 'k'   : (0x69, 0x7c, 0x73),
    'l'   : (0x61, 0x3a, 0x35), 'm'   : (0x63, 0x5f, 0x61),
    'n'   : (0x50, 0x65, 0x4b), 'o'   : (0x67, 0x46, 0x58),
    'p'   : (0x51, 0x58, 0x3b), 'q'   : (0x49, 0x31, 0x57),
    'r'   : (0x4f, 0x69, 0x22), 's'   : (0x46, 0x6c, 0x6d),
    't'   : (0x68, 0x5a, 0x4d), 'u'   : (0x7c, 0x48, 0x25),
    'v'   : (0x36, 0x27, 0x28), 'w'   : (0x70, 0x5c, 0x46),
    'x'   : (0x6e, 0x3d, 0x4a), 'y'   : (0x7a, 0x24, 0x32),
    'z'   : (0x2f, 0x79, 0x41), '{'   : (0x5f, 0x37, 0x3d),
    '|'   : (0x4b, 0x60, 0x5f), '}'   : (0x5a, 0x51, 0x4f),
    '~'   : (0x2c, 0x20, 0x42), '\x7f': (0x57, 0x36, 0x65)
}

if __name__ == '__main__':
    main()

