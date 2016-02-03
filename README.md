[![Build Status](https://travis-ci.org/keybase/saltpack-python.svg?branch=master)](https://travis-ci.org/keybase/saltpack-python)

A Python implementation of [saltpack](https://saltpack.org/). You can
play with commands like:

```
saltpack encrypt -m "foo" | saltpack decrypt --debug
```

Install with `pip` or `pip3`, depending on what your system calls Python
3's version of `pip`:

```
pip install saltpack
```

A brief summary of the commands:

- **encrypt** and **decrypt** deal with encrypted messages. Use the
  `--binary` flag to skip the ASCII armoring. The default private key is
  32 zero bytes, and the default recipients list is just the sender.
  They will read from stdin unless you provide the `--message` flag.
- **sign** and **verify** deal with signed messages. The default private
  key is randomly generated. These also understand `--binary` and
  `--message`. The `--detached` flag (for signing) and the `--signature
  <file>` flag (for verifying) invoke the detached signing mode.
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
