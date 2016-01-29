[![Build Status](https://travis-ci.org/keybase/saltpack-python.svg?branch=master)](https://travis-ci.org/keybase/saltpack-python)

A Python implementation of
[saltpack](https://github.com/keybase/client/blob/master/go/saltpack/specs).
You can play with commands like:

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
