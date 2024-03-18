# SMSWithoutBorders - LibSig


## Requirements
A shared secret is required to initialize the Ratchets. 

This can be achieved by performing a DH handshake between the parties,
both of them store their public keys and whomever messages first becomes Alice.

**Not in the scope of this document.**


It is important to know who is initializing the messages.

For server/client, the server key can be stored on the client,
allowing the client to always initialize the conversation.

Client = Alice

Server = Bob

```python
alice = Person('Alice')

bob = Person('Bob')

```

After handshakes, messages can now be exchanged..

```python
# ------- On Sending the message ----

bobs_public_key = ...

"""
Header has to be transmitted alongside cipher text.

Protocol used for sending header and cipher text 
would depend on developer.
"""
header: Header, cipher_text: bytes = \
    alice.send_message(message='hello world', AD=bobs_public_key)

header_serialized: bytes = header.serialize()


# ------- On receiving the message ----

header, cipher_text = get_alice_messages()

message = bob.read_message(header, cipher_text, AD)
```
