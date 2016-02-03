[![Build Status](https://travis-ci.org/keybase/saltpack-python.svg?branch=master)](https://travis-ci.org/keybase/saltpack-python)

A Python implementation of [saltpack](https://saltpack.org/). You can
play with commands like:

```
saltpack encrypt -m "foo" | saltpack decrypt --debug
```

(Commands like `encrypt` and `sign` that normally require a private key,
will fall back to some default key if you don't provide one, to make it
easier to play with the format.)

You can install this package with:

```
pip install saltpack
```

Requires Python 3, which may mean you need to use `pip3` instead of
`pip`.

A brief summary of the commands:

- **encrypt** and **decrypt** deal with encrypted messages. Use the
  `--binary` flag to skip the ASCII armoring. The default private key is
  32 zero bytes, and the default recipients list is just the sender.
  They will read from stdin unless you provide the `--message` flag.
- **sign** and **verify** deal with signed messages. These also
  understand `--binary` and `--message`. The `--detached` flag (for
  signing) and the `--signature <file>` flag (for verifying) invoke the
  detached signing mode.
- **armor** and **dearmor** commands read input from stdin and either
  encode it or decode it with saltpack's base 62 ASCII armor. The
  `--raw` flag skips the "BEGIN..." header and "END..." footer. Note
  that the header produced by this command doesn't describe the message
  type (i.e. "BEGIN SALTPACK ENCRYPTED MESSAGE"), so prefer **encrypt**
  and **sign**'s built-in armoring.
- **block** and **unblock** are low level command for playing with the
  BaseX encoding scheme that underlies our base 62 ASCII armor.
- **efficient** prints out a list of efficient BaseX block sizes for a
  given alphabet size.
