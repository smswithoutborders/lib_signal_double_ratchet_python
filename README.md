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
from dh import x25519

client1 = x25519()

# pnt_keystore:- store to fetch the private key later
# enc_key:- required to decrypt the encrypted sql file (if encrypted)
client1_public_key, pnt_keystore, enc_key = client1.get_public_key()

client2 = x25519()
client2_public_key, pnt_keystore1, enc_key1 = client2.get_public_key()

# Agreement
private_keystore_path1 = "db_keys/client1.db"
private_keystore_path2 = "db_keys/client2.db"
# paths default to "db_keys/<pnt_keystore1>.db" when null

client1 = x25519(pnt_keystore, private_keystore_path1)
client2 = x25519(pnt_keystore1, private_keystore_path2)
# dk:- shared secret
dk = client1.agree(client2_public_key, pnt_keystore, enc_key)
dk1 = client2.agree(client1_public_key, pnt_keystore1, enc_key1)

assert(dk != None)
assert(dk1 != None)

assert(dk == dk1)
```
