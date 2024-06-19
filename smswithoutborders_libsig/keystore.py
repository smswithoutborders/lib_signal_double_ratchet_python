#!/usr/bin/env python3

# import libsig
import os
if os.environ.get("NOSECURE"):
    import sqlite3 as sqlite
else:
    import sqlcipher3 as sqlite


class Keystore:
    table_name = "_crypto"
    def __init__(self, db_name, mk):
        self.mk = mk
        self.conn = sqlite.connect(db_name)
        self.cursor = self.conn.cursor()

        self.create()

    def create(self):
        self.cursor.execute(f"PRAGMA key = '{self.mk}'")
        self.cursor.execute(f"PRAGMA cipher_compatibility = 3")
        self.cursor.execute(f'''
        CREATE TABLE IF NOT EXISTS {self.table_name} (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            pnt TEXT NOT NULL UNIQUE,
            pk BLOB NOT NULL, _pk BLOB NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        ''')

    def store(self, keypair: tuple, pnt): # (public, private)
        pk = keypair[0]
        _pk = keypair[1]
        # pk = libsig.ENCRYPT(mk, keypair[0], b"public_key")
        # _pk = libsig.ENCRYPT(mk, keypair[1], b"private_key")
        self.cursor.execute(f"PRAGMA key = '{self.mk}'")
        self.cursor.execute(f"PRAGMA cipher_compatibility = 3")
        self.cursor.execute(f'INSERT INTO {self.table_name} (pnt, pk, _pk) VALUES (?, ?, ?)', 
                       (pnt, pk, _pk,))

        auto_id = self.cursor.lastrowid

        # Commit the transaction and close the connection
        self.conn.commit()

        return auto_id

    def fetch(self, pnt):
        self.cursor.execute(f"PRAGMA key = '{self.mk}'")
        self.cursor.execute(f"PRAGMA cipher_compatibility = 3")
        self.cursor.execute(f'SELECT * FROM {self.table_name} WHERE pnt = ?', (pnt,))
        rows = self.cursor.fetchall()

        pk_values = []
        for row in rows:
            # pk = libsig.DECRYPT(mk, row[1], b"public_key")
            # _pk = libsig.DECRYPT(mk, row[2], b"private_key")
            pk = row[2]
            _pk = row[3]
            pk_values.append((pk, _pk))

        return None if len(pk_values) < 1 else pk_values[0]

if __name__ == "__main__":
    # mk = (b"123abc"*6)[:32]
    mk = ("123abc"*6)[:32]
    if os.environ.get("NOSECURE"):
        keystore = Keystore("db_keys/temp_plain.db", mk)
    else:
        keystore = Keystore("db_keys/temp_sec.db", mk)

    data = (b"hello", b"world")
    keystore.store(data)

    rows = keystore.fetch()[0]
    assert(data == rows)
