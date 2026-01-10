
import os
from smswithoutborders_libsig.protocols import (
    States,
    HEADERS,
    GENERATE_DH,
    DH,
    KDF_CK,
    ENCRYPT,
    DECRYPT,
    CONCAT,
    DHRatchet,
)

from smswithoutborders_libsig.keypairs import x25519
    
class RatchetsHE:
    """
    A class to handle the ratchet mechanism.
    """

    @staticmethod
    def alice_init_HE(
        state: States, 
        SK: bytes, 
        bob_dh_public_key: bytes, 
        shared_hka: bytes, 
        shared_nhkb: bytes,
        keystore_path: str = None
    ):
        """
        Initializes the state for Alice.

        Args:
            state (States): The state to be initialized.
            SK (bytes): The shared secret key.
            bob_dh_public_key (bytes): Bob's public Diffie-Hellman key.
            keystore_path (str, optional): The path to the keystore. Defaults to None.
        """
        state.DHRs = GENERATE_DH(keystore_path)
        state.DHRr = bob_dh_public_key
        state.RK, state.CKs, state.NHKs = KDF_RK_HE(SK, DH(state.DHRs, state.DHRr))
        state.CKr = None
        state.Ns = 0
        state.Nr = 0
        state.PN = 0
        state.MKSKIPPED = {}
        state.HKs = shared_hka
        state.MKSKIPPED = None
        state.MKSKIPPED = shared_nhkb

    @staticmethod
    def bob_init_HE(
        state: States, 
        SK: bytes, 
        bob_dh_key_pair: x25519, 
        shared_hka: bytes, 
        shared_nhkb: bytes
    ):
        """
        Initializes the state for Bob.

        Args:
            state (States): The state to be initialized.
            SK (bytes): The shared secret key.
            bob_dh_key_pair (Keypairs): Bob's Diffie-Hellman key pair.
        """
        state.DHs = bob_dh_key_pair
        state.DHr = None
        state.RK = SK
        state.CKs = None
        state.CKr = None
        state.Ns = 0
        state.Nr = 0
        state.PN = 0
        state.MKSKIPPED = {}
        state.HKs = None
        state.NHKs = shared_nhkb
        state.HKr = None
        state.NHKr = shared_hka

    @staticmethod
    def RatchetEncryptHE(*, state: States, data: bytes, AD: bytes):
        """
        Encrypts data using the current state.

        Args:
            state (States): The current state.
            data (bytes): The data to be encrypted.
            AD (bytes): The associated data.

        Returns:
            tuple: A tuple containing the header and the encrypted data.
        """
        state.CKs, mk = KDF_CK(state.CKs)
        header = HEADERS(state.DHRs, state.PN, state.Ns)
        enc_header = HENCRYPT(state.HKs, header)
        state.Ns += 1
        return enc_header, ENCRYPT(mk, data, CONCAT(AD, enc_header))

    @staticmethod
    def RatchetDecryptHE(
        *, 
        state: States, 
        enc_header: HEADERS, 
        ciphertext: bytes, 
        AD: bytes
    ) -> bytes:
        """
        Decrypts data using the current state.

        Args:
            state (States): The current state.
            header (HEADERS): The header of the encrypted message.
            ciphertext (bytes): The encrypted data.
            AD (bytes): The associated data.

        Returns:
            bytes: The decrypted data.
        """
        plaintext = Ratchets.TrySkippedMessageKeysHE(state, enc_header, ciphertext, AD)
        if plaintext:
            return plaintext

        header, dh_ratchet = DecryptHeader(state, enc_header)
        if dh_ratchet:
            Ratchets.SkipMessageKeysHE(state, header.pn)
            DHRatchet(state, header)

        Ratchets.SkipMessageKeysHE(state, header.n)
        state.CKr, mk = KDF_CK(state.CKr)
        state.Nr += 1
        return DECRYPT(mk, ciphertext, CONCAT(AD, enc_header))


    @staticmethod
    def TrySkippedMessageKeysHE(
        state: States, 
        enc_header: HEADERS, 
        ciphertext: bytes, 
        AD: bytes
    ) -> bytes:
        """
        Tries to skip message keys if they are already present in the skipped keys.

        Args:
            state (States): The current state.
            header (HEADERS): The header of the encrypted message.
            ciphertext (bytes): The encrypted data.
            AD (bytes): The associated data.

        Returns:
            bytes: The decrypted data if a skipped key is found, else None.
        """
        for ((hk, n), mk) in state.MKSKIPPED.items():
            header = HDECRYPT(hk, enc_header)
            if header != None and header.n == n:
                del state.MKSKIPPED[hk, n]
                return DECRYPT(mk, ciphertext, CONCAT(AD, enc_header))

        return None
    
    @staticmethod
    def SkipMessageKeysHE(state: States, until: int):
        """
        Skips message keys until a certain number is reached.

        Args:
            state (States): The current state.
            until (int): The number until which to skip message keys.

        Raises:
            Exception: If the number of skipped keys exceeds MAX_SKIP.
        """
        if state.Nr + Ratchets.MAX_SKIP < until:
            raise Exception("MAX_SKIP Exceeded")

        if state.CKr:
            while state.Nr < until:
                state.CKr, mk = KDF_CK(state.CKr)
                state.MKSKIPPED[state.HKr, state.Nr] = mk
                state.Nr += 1

    @staticmethod
    def DecryptHeader(state, enc_header):
        header = HDECRYPT(state.HKr, enc_header)
        if header != None:
            return header, False
        header = HDECRYPT(state.NHKr, enc_header)
        if header != None:
            return header, True
        raise Error()

