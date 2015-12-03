# SillyBox

## Encryption

### Design goals
We want this format to have several properties:
- Privacy and authenticity. This is pretty standard. Mallory shouldn't be able
  to read or modify the contents of the message. (Though Mallory can see the
  length of the message.)
- Repudiability. Recipients should be able to forge messages that appear to be
  sent to them.
- Receiver anonymity. Mallory shouldn't be able to tell who can read the
  message. (Though Mallory can see the number of recipients.)
- Sender anonymity. Mallory shouldn't be able to tell who wrote the message.
- Streaming. The recipient should be able to produce decrypted bytes
  incrementally as the message comes in, without losing authenticity. (Though
  without reading all the way to the end, the message might end up being
  truncated.)

A couple notes:
- Authenticity should apply even if Mallory is one of the recipients. It
  shouldn't be possible for one recipient to change what another recipient
  sees.
- Receiver anonymity is optional. With visible receivers, clients can give
  helpful decyption instructions like, "To read this message, type in your
  paper key 'Foo Bar'." But note that visible receivers aren't authenticated;
  Mallory could change them.

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
