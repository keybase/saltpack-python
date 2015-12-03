# SillyBox

## Encryption

### Thinking
Our goals for encrypted messages:
- Message privacy and authenticity, to many recipients. Mallory can't read or
  modify the contents of a message. (Though Mallory can see the length.)
  - Even if Mallory is a recipient, they still can't modify the message for
    anyone else.
- Receiver privacy. Mallory can't tell who can read a message. (Though Mallory
  can see the number of recipients.)
  - Again this applies even if Mallory is a recipient.
  - However, senders have the option of publishing the recipients. That helps
    clients give instructions like, "To read this message, use [some other
    device]." Note that Mallory could modify the published recipients.
- Sender privacy. Mallory can't tell who wrote a message, even though
  recipients see and verify the sender.
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
An encrypted message is a series of packets, each of which is parsed as a
MessagePack array:
- a header packet
- any number of non-empty payload packets
- an empty payload packet, marking the end of the message

The contents of the header packet array are:
- the format name string ("sillybox")
- the format version int (1)
- the sender ephemeral public key (32 bytes)
- an array or recipient sets

Each recipient set is formatted as array:
- the recipient public key (optional, either 32 bytes or null)
- the sender box
  - encrypted with the ephemeral private key
  - contains the 32-byte public sender key
- the keys box
  - encrypted with the sender private key
