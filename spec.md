# Encryption

## Properties
NaCl boxes have several properties that we want to keep:
- Privacy and authenticity. Mallory can't read or modify a message.
- Repudiability. Bob can forge a message that appears to be from Alice to Bob.
- Sender and recipient privacy. An encrypted message doesn't reveal who wrote
  it or who can read it.

Building on what NaCl gives us, there are several other properties we want:
- Multiple recipients.
- Streaming. We want to be able to decrypt a message of any size without
  needing to fit the whole thing in RAM.
- Abuse resistance. Alice might use the same encryption key for many
  applications besides Sillybox. Mallory might try to trick Alice into
  decrypting ciphertexts from other applications, by formatting them as part of
  a Sillybox message. Alice shouldn't be able to decrypt these messages at all.

## Format

An encrypted message is an encryption header packet, followed by any number of
non-empty payload packets, followed by an empty payload packet. The default max
size for each payload is 1MB.

```yaml
# encryption header object
[
  # format name
  "sillybox",
  # major version
  1,
  # minor version
  0,
  # mode (0 = encryption)
  0,
  # ephemeral sender public key (NaCl crypto_box key, 256 bits)
  b"ababab...",
  # recipients list
  [
    # set of boxes for a single recipient
    [
      # recipient key (NaCl crypto_box key, 256 bits, or null)
      b"d3d3d3..."
      # encrypted sender key box (NaCl crypto_box)
      b"a2a2a2..."
      # encrypted message keys box (NaCl crypto_box)
      b"c5c5c5..."
    ],
    # additional recipients...
  ]
]
```

An encryption payload is a MessagePack object shaped like this:

```yaml
[
  # list of MACs (NaCl crypto_auth, 256 bits)
  [
    b"e6e6e6...",
    # additional MACs...
  ],
  # encrypted payload box (NaCl crypto_box)
  b"f8f8f8..."
]
```

When encrypting a message, the sender generates a random ephemeral keypair. The
ephemeral public key goes directly in the header above. The sender key box for
each recipient is encrypted with the ephemeral private key and the recipient's
public key, and it contains contain the sender's long-term public key (NaCl
crypto_box key, 256 bits). The message keys box for each recipient is encrypted
with the sender's long-term private key and each recipient's public key, and
it contains a MessagePack array with several values:

```yaml
[
  # symmetric encryption key (NaCl crypto_secretbox key, 256 bits)
  b"4a4a4a...",
  # MAC group (a 32-bit signed int, serialized to 4 bytes)
  b"00000000",
  # MAC key (NaCl crypto_auth key, 256 bits)
  b"2b2b2b...",
]
```

The symmetric encryption key is the same for every recipient, and it opens the
payload box in each payload packet. The MAC group tells the recipient which MAC
to use, as an index into each payload packet's MACs list. The MAC key is the
same for every recipient in the same MAC group. The goal of MAC groups is that
it should be possible to make one MAC for all the recipient devices that belong
to a single person, rather than requiring a separate MAC for every recipient
device, to save space when recipients have many devices.

The MACs are computed over the first 16 bytes of each payload box (the Poly1305
authenticator) concatenated with the packet number. The packet number is a
192-bit big-endian uint, where the first payload packet is zero. This value is
also the nonce for the payload box, see below.

### Nonces

The 192-bit nonce for each sender key box is (TODO) b"SOME_160_BIT_CONSTANT"
concatenated with the recipient index as a 32-bit big-endian uint.

The nonce for each message keys box is the first 160 bits of the SHA512 of the
ephemeral sender key, concatenated with the recipient index as a 32-bit
big-endian uint.

The nonce for each payload box is the packet number as a 192-bit big-endian
uint, where the first payload packet is zero.

The goal with the first two nonces is that an attacker who's trying to trick us
into decrypting some non-SillyBox ciphertext, shouldn't be able to control the
nonce that we use, so our decryption should fail.

TODO: Fill this out.


<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<






```yaml
# attached signing header object
[
  # format name
  "silly box",
  # major version
  1,
  # minor version
  0,
  # mode (1: attached signing)
  1,
  # signing key
  b"ababab...",
]

# signing payload object





















## Encryption

### Thinking
Our goals for encrypted messages:
- Message privacy and authenticity, to many recipients. Mallory can't read or
  modify the contents of a message. (Though Mallory can see the length.)
  - Even if Mallory is a recipient, she still can't modify the message for
    anyone else.
- Receiver privacy. Mallory can't tell who can read a message. (Though Mallory
  can see the number of recipients.)
  - Again this applies even if Mallory is a recipient.
  - However, senders have the option of publishing the recipients. That helps
    clients give instructions like, "To read this message, use [some other
    device]." Note that Mallory could modify the published recipients.
- Sender privacy. Mallory can't tell who wrote a message, even though
  recipients can see and verify the sender.
  - Senders who want to be anonymous even to the recipients, can use an
    ephemeral key instead of their usual public key.
- Repudiability. Recipients can forge messages that appear to be sent to them
  from any sender.
- Streaming. Recipients can produce decrypted bytes incrementally as a message
  comes in, without losing authenticity. (Though the message could be
  truncated.)

Our goals for the implementation:
- Use MessagePack for all the serialization.
- Use NaCl primitives for all the crypto: Box, SecretBox, SHA512, and
  HMAC-SHA512.

### Format
An encrypted message is a series of MessagePack objects:
- a header packet
- any number of non-empty payload packets
- an empty payload packet, marking the end of the message

The contents of the header packet array are:
- the format name string ("sillybox")
- the major version (1)
- the minor version (0)
- the mode (encryption, or attached/detached signing)
- an ephemeral public key (32 bytes)
- an array of **recipient sets**

A **recipient set** is also an array:
- the recipient public key (optional, either 32 bytes or null)
- the sender box
  - encrypted with the ephemeral private key
  - contains the 32-byte public sender key
- the keys box
  - encrypted with the sender's private key
  - contains a **key set**, as MessagePack bytes

A **key set** is yet another array:
- a 32-byte symmetric encryption key
  - This is the same for all recipients.
- a MAC group number
  - TODO: How do we fix the length of this?
- a 32-byte symmetric MAC key
  - This is shared by each recipient in the same MAC group. While every
    recipient could be in their own group, the intention is that a MAC group
    could represent a single person's collection of devices.
  - TODO: Omit MACing when there's only one MAC group?

The contents of a payload packet array are:
- an array of MACs
  - The index of each MAC in the array is the MAC group number from above.
  - The key is the symmetric MAC key for that group number.
  - The input to each MAC is the concatenation of two values:
    - the Poly1305 tag (the first 16 bytes) of the chunk box, below
    - the chunk index, as an 8-byte big-endian unsigned integer
- a chunk secret box
  - encrypted with the symmetric encryption key
- The packet contents, a MessagePack bin object. The maximum size of a bin
  object is about 4GB, but our default size will be 1MB.

An empty chunk signifies the end of the message.

## Example
A message with one recipient.
```
# header
[
  "sillybox",
  1,
  0,
  0,
  b"f5LbalfieMFlFalEPq2nYJi0InXd2TZRv/JDpMSCZCs=",
  [
    [
      null,
      b"EwaiG9lb78s/ZBhqss0PO7II2jW517fMeqNjyDRQqLJatnWUm+3DyXbPyINopLbE",
      b"wydMHuq5xI5GTYJF5MQUI9x2vgIMdJ2GK9KDVGSiJ1D6NuWfSs2dhGL7B+uFlcZi3irCqL2xOwVrVNzEI2o4VvFWeayLmpWmxeB42svFuRc1dn8uHOk="
    ]
  ]
]

# keys set (decrypted and unpacked)
[
  b"KYhzlhoUSBoZrtTcgKfKJo3tpTl0MkPHTKIwp0Xabj0=",
  0,
  b"np0Z7kdR8o8SLxnh0kb2AHZYgnSGTpU4oVGBTVbm2RY="
]

# packet 0
[
  [
    b"3xGnG2O9hgYV2BEQPBxbqvTTDQQeeCbW5ln5a9NoEr0="
  ],
  b"ailuqv38FS9zqIHRUvMpHaUpJzWa1ZPvZk8OzZzv4tECBwMJmwioGfb8P03vb62h2F8JNJlrgQ=="
]

# chunk 0 (decrypted)
'The Magic Words are Squeamish Ossifrage'

# packet 1
[
  [
    b"26oYynh1UeVV4xfo7RjpbCZ+bGa9miSM5qKR/KSpBlw="
  ],
  b"s1jqk6ILx7WsNZ2nJzyLEw=="
]

# chunk 1 (decrypted)
''
```

## Signing

### Format
Similar to encryption. A signed message is a series of packets, each of which
is a MessagePack array:
- a header packet
- any number of non-empty payload packets
- an empty payload packet, marking the end of the message

The contents of the header packet are:
- the format name
- the major version (1)
- the minor version (0)
- the mode number
- the signing public key

In detached mode, there is no payload, and the header contains an extra field:
- the detached NaCl sig of the SHA512 of the message
- TODO: concatenated with some other stuff?!

In attached mode, as in encryption mode, the header is followed by a number of
payload packets. Each payload packet contains:
- an attached NaCl sig of an ephemeral signing public key
  - signed by the sender for the first packet, or the previous ephemeral key
    for subsequent packets
  - TODO: concatenated with some other stuff?!
- an attached NaCl sig of the message chunk
  - signed by the ephemeral key above

An empty chunk signifies the end of the message.

### Attached
[
  "sillybox"
  1          # version
  1          # mode (attached signing)
  abc123...  # signer pk
]
[
  def456...  # first ephemeral pk carton, signed by signer
             # TODO: Should there be extra constants in this carton?
  c2c2c2...  # payload carton, signed by first ephemeral
]
...
[
  dadada...  # next ephemeral pk carton, signed by previous
  c2c2c2...  # next payload carton, signed by current
]
[
  5b5b5b...  # final ephemeral pk carton, signed by previous
  929292...  # empty carton, signed by current
]



[
  "sillybox"
  1          # version
  1          # mode (attached signing)
  abc123...  # signer pk
  Sig[signer](ephemeral_pk + SILLYBOX_SUFFIX)
]

[
  Sig[ephemeral](chunk + 64_bit_seqno)
]



### Detached
[
  "sillybox"
  1          # major version
  0          # minor version
  2          # mode (detached signing)
  5d5d5d...  # sender
  afafaf...  # detached sig of SHA512 of payload
             # TODO: Should there be extra constants in this hash?
]


# TODO
think about take over attacks
- never sign anything we didn't generate
- how can we be careful about what we decrypt?

Nonce:
  - for the sender box: "FIXED_PREFIX" + receiver_index
  - for the keys box: hash(another_prefix+ephemeral) + receiver_index
  - Never decrypt something that isn't a valid SillyBox message. The first box
    has a totally constant nonce that should never collide with another
    application. The second box uses a nonce that's difficult for the attacker
    to control.
  - The fixed prefixes are parameters of the implementation. Applications that
    don't want signature compatibility (like for example, the sigchain?) should
    change the prefixes.

can we get a constant file prefix?
- what does `file` do?

use Major.Minor versioning (Fred's idea)
