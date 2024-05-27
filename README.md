# SMSWithoutBorders - LibSig

## Installation

```bash
pip3 install -r requirements.txt
```
<br>

> Install if planning to use `pysqlcipher3`

**Arch**
```bash
sudo pacman -S sqlcipher
```

**Ubuntu**
```bash
sudo apt-get install libsqlcipher-dev
sudo apt install build-essential git cmake libsqlite3-dev
sudo apt install sqlcipher
```


## DH Key exchanges Examples
```python3
from keypairs import x25519

alice = x25519()
alice_public_key_original = alice.init()

bob = x25519("db_keys/bobs_keys.db")
bob_public_key_original = bob.init() # not an encryption key, won't work unless for AD

SK = alice.agree(bob_public_key_original)
SK1 = bob.agree(alice_public_key_original)

assert(SK)
assert(SK1)
assert(SK == SK1)
```
