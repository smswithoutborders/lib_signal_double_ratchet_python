#!/usr/bin/env python3

# from pysqlcipher import dbapi2 as sqlite
from 
import libsig

class Keystore:
    table_name = "_crypto"
    def __init__(self, db_name):
        self.conn = sqlite.connect(db_name)
        self.cursor = self.conn.cursor()

        self.create()

    def create(self):
        self.cursor.execute(f'''
        CREATE TABLE IF NOT EXISTS {self.table_name} (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            pk BLOB NOT NULL, _pk BLOB NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        ''')

    def store(self, keypair: tuple, mk): # (public, private)
        # pk = libsig.ENCRYPT(mk, keypair[0], b"public_key")
        # _pk = libsig.ENCRYPT(mk, keypair[1], b"private_key")
        self.cursor.execute(f"PRAGMA key = '{mk}'")
        self.cursor.execute(f'INSERT INTO {self.table_name} (pk, _pk) VALUES (?, ?)', 
                       (pk, _pk,))

        # Commit the transaction and close the connection
        self.conn.commit()

    def fetch(self, mk):
        self.cursor.execute(f"PRAGMA key = '{mk}'")
        self.cursor.execute(f'SELECT * FROM {self.table_name}')
        rows = self.cursor.fetchall()

        pk_values = []
        for row in rows:
            print(f"+ decrypting {row[0]}...")
            # pk = libsig.DECRYPT(mk, row[1], b"public_key")
            # _pk = libsig.DECRYPT(mk, row[2], b"private_key")
            pk = row[1]
            _pk = row[2]
            pk_values.append((pk, _pk))

        return pk_values

if __name__ == "__main__":
    mk = (b"123abc"*6)[:32]
    keystore = Keystore("db_keys/temp.db")

    data = (b"hello", b"world")
    keystore.store(data, mk)

    rows = keystore.fetch(mk)[0]
    assert(data == rows)
