#!/usr/bin/env python3
import argparse
import os

from smswithoutborders_libsig.keypairs import x25519
from smswithoutborders_libsig.keystore import Keystore

"""
python3 -m smswithoutborders_libsig.generate
"""

if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog='')

    # parser.add_argument("--key", type=str, required=True, help="Encryption Key")
    parser.add_argument("--destination", type=str, required=True, help="Relative path to write encryption file")


    args = parser.parse_args()

    DN = args.destination if args.destination else "generated.db"

    overwrite = None
    if os.path.isfile(DN):
        overwrite = input(f"File at {DN} already exists. Override? (y/N):")
        overwrite = True if overwrite == 'y' else False
        if overwrite:
            os.remove(DN)
            print(f"Overwriting file: {DN}")

    if overwrite == None or overwrite == True:
        keypairs = x25519(keystore_path=DN)
        pk = keypairs.init()
        print("pubkey: \n", pk)
        print("pnt_keystore: \n", keypairs.pnt_keystore)
        print("secret: \n", keypairs.secret_key)

        keystore = Keystore(DN, keypairs.secret_key)
        rows = keystore.fetch(keypairs.pnt_keystore)
        print("rows:", rows)
        assert rows != None and len(rows) == 2