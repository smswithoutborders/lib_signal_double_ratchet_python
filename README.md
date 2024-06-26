# SMSWithoutBorders - LibSig

## Installation

```bash
pip3 install -r requirements.txt
```

<br>

> [!NOTE]
>
> If you plan to use `pysqlcipher3`, you'll need to install additional system
> dependencies.

**Arch**

```bash
sudo pacman -S sqlcipher
```

**Ubuntu**

```bash
sudo apt-get install libsqlcipher-dev
sudo apt install build-essential git cmake libsqlite3-dev
```

> [!TIP]
>
> You can install these system dependencies automatically using the
> `install_system_deps.py` script.

```bash
python install_system_deps.py
```

## Installing the Package via Pip

```bash
pip install "git+https://github.com/smswithoutborders/lib_signal_double_ratchet_python.git@main#egg=smswithoutborders_libsig"
```

## DH Key exchanges Examples

```python
from smswithoutborders_libsig.keypairs import x25519

alice = x25519()
alice_public_key_original = alice.init()

bob = x25519("db_keys/bobs_keys.db")
bob_public_key_original = bob.init() # not an encryption key, won't work unless for AD

SK = alice.agree(bob_public_key_original)
SK1 = bob.agree(alice_public_key_original)

# store the following
alice_pnt_keystore = alice.pnt_keystore
alice_secret_key = alice.secret_key # used to decrypt the keystore sql file

# reinitializing would be...
alice = x25519(pnt_keystore=alice_pnt_keystore, keystore_path=alice_keystore_path, secret_key=alice_secret_key)

assert(SK)
assert(SK1)
assert(SK == SK1)
```

## Double Ratchet Implementations

- States must be stored
```python
ss: bytes = states.serialize()
---
states: States = States.deserialize(ss)
```

- Headers can be transmitted by serializing them
```python
transmission_bytes: bytes = headers.serialize()

---

header = HEADER.deserialize(transmission_bytes)
```

```python
# perform the above DH handshake and derive an SK
server_keypair = ...

server_public_key = server_keypair.init()

"""
[+] Information which should be stored from doing the ratchet include:

- server_keypair.pnt_keystore: str

- server_keypair.secret_key: bytes
"""
...

original_plaintext = b"Hello world"

client_state = States()
server_state = States()

client_key_filepath = "db_keys/alice_keys.db"
Ratchets.alice_init(client_state, SK, bob_public_key_original, client_key_filepath)
header, client_ciphertext = Ratchets.encrypt(client_state, original_plaintext, server_public_key)

# sample transmission could have
len_header = len(header.serialize())
transmission_text = base64.b64encode(struct.pack("<i", len_header) + header + client_ciphertext)

...

server_key_filepath = f"db_keys/{client_identification_details}.db"
server = x25519(server_key_filepath)
server.load_keystore(server_keypair.pnt_keystore, server_keypair.secret_key)

Ratchets.bob_init(server_state, SK1, server)
server_plaintext = Ratchets.decrypt(server_state, header, client_ciphertext, bob_public_key_original)

assert(original_plaintext == server_plaintext)
```
