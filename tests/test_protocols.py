"""Tests for protocol components."""

import os
import secrets

import pytest

from smswithoutborders_libsig.keypairs import x25519
from smswithoutborders_libsig.protocols import (
    CONCAT,
    DECRYPT,
    DH,
    ENCRYPT,
    GENERATE_DH,
    HEADERS,
    KDF_CK,
    KDF_RK,
    DHRatchet,
    States,
)
from tests.test_helpers import headers_equal, states_equal


class TestStates:
    """Test States serialization and deserialization."""

    def setup_method(self):
        self.keystore_path = "db_keys/test_states.db"
        self.dh_keypair = x25519(keystore_path=self.keystore_path)
        self.dh_keypair.init()

    def teardown_method(self):
        if os.path.exists(self.keystore_path):
            os.remove(self.keystore_path)

    def test_state_initialization(self):
        """Test States initializes with default values."""
        state = States()
        assert state.DHs is None
        assert state.RK is None
        assert state.Ns == 0
        assert state.MKSKIPPED == {}

    def test_state_serialization_roundtrip(self):
        """Test States serialization and deserialization."""
        state = States()
        state.DHs = self.dh_keypair
        state.RK = secrets.token_bytes(32)
        state.DHr = secrets.token_bytes(32)
        state.CKs = secrets.token_bytes(32)
        state.CKr = secrets.token_bytes(32)
        state.Ns = 5
        state.Nr = 3
        state.PN = 2
        state.MKSKIPPED = {(b"key1", 1): b"value1"}

        serialized = state.serialize()
        deserialized = States.deserialize(serialized)

        assert states_equal(deserialized, state)
        assert deserialized.Ns == 5
        assert deserialized.MKSKIPPED == {(b"key1", 1): b"value1"}

    def test_state_serialization_requires_fields(self):
        """Test serialization requires DHs and RK."""
        state = States()
        with pytest.raises(Exception, match="State cannot be serialized"):
            state.serialize()

    def test_state_serialization_with_none_values(self):
        """Test States handles None values."""
        state = States()
        state.DHs = self.dh_keypair
        state.RK = secrets.token_bytes(32)
        state.DHr = secrets.token_bytes(32)
        state.CKs = None
        state.CKr = None

        serialized = state.serialize()
        deserialized = States.deserialize(serialized)

        assert deserialized.CKs is None
        assert deserialized.CKr is None

    def test_states_equality(self):
        """Test states comparison."""
        state1 = States()
        state1.DHs = self.dh_keypair
        state1.RK = secrets.token_bytes(32)
        state1.Ns = 1

        state2 = States()
        state2.DHs = self.dh_keypair
        state2.RK = secrets.token_bytes(32)
        state2.Ns = 2

        assert not states_equal(state1, state2)


class TestHEADERS:
    """Test HEADERS serialization."""

    def setup_method(self):
        self.keystore_path = "db_keys/test_headers.db"
        self.dh_keypair = x25519(keystore_path=self.keystore_path)
        self.dh_keypair.init()

    def teardown_method(self):
        if os.path.exists(self.keystore_path):
            os.remove(self.keystore_path)

    def test_header_serialization_roundtrip(self):
        """Test HEADERS serialization and deserialization."""
        header1 = HEADERS(dh_pair=self.dh_keypair, pn=5, n=10)
        serialized = header1.serialize()
        header2 = HEADERS.deserialize(serialized)

        assert headers_equal(header1, header2)
        assert header2.pn == 5
        assert header2.n == 10

    def test_headers_equality(self):
        """Test headers comparison."""
        header1 = HEADERS(dh_pair=self.dh_keypair, pn=5, n=10)
        header2 = HEADERS(dh_pair=self.dh_keypair, pn=6, n=10)

        assert not headers_equal(header1, header2)


class TestDHRatchet:
    """Test DH operations."""

    def setup_method(self):
        self.keystore_path1 = "db_keys/test_dh1.db"
        self.keystore_path2 = "db_keys/test_dh2.db"

    def teardown_method(self):
        for path in [self.keystore_path1, self.keystore_path2]:
            if os.path.exists(path):
                os.remove(path)

    def test_dh_agreement(self):
        """Test DH key agreement."""
        dh1 = GENERATE_DH(keystore_path=self.keystore_path1)
        dh2 = GENERATE_DH(keystore_path=self.keystore_path2)

        shared1 = DH(dh1, dh2.get_public_key())
        shared2 = DH(dh2, dh1.get_public_key())

        assert shared1 == shared2
        assert len(shared1) == 32

    def test_dh_ratchet_updates_state(self):
        """Test DHRatchet updates state."""
        state = States()
        state.DHs = GENERATE_DH(keystore_path=self.keystore_path1)
        state.RK = secrets.token_bytes(32)
        state.Ns = 5

        dh_remote = GENERATE_DH(keystore_path=self.keystore_path2)
        header = HEADERS(dh_pair=dh_remote, pn=0, n=0)

        DHRatchet(state, header)

        assert state.PN == 5
        assert state.Ns == 0
        assert state.CKr is not None
        assert state.CKs is not None


class TestKDF:
    """Test key derivation functions."""

    def test_kdf_rk(self):
        """Test KDF_RK generates deterministic keys."""
        rk = secrets.token_bytes(32)
        dh_out = secrets.token_bytes(32)

        new_rk1, ck1 = KDF_RK(rk, dh_out)
        new_rk2, ck2 = KDF_RK(rk, dh_out)

        assert new_rk1 == new_rk2
        assert ck1 == ck2
        assert len(new_rk1) == 32

    def test_kdf_ck(self):
        """Test KDF_CK generates deterministic keys."""
        ck = secrets.token_bytes(32)

        new_ck1, mk1 = KDF_CK(ck)
        new_ck2, mk2 = KDF_CK(ck)

        assert new_ck1 == new_ck2
        assert mk1 == mk2
        assert len(new_ck1) == 32


class TestEncryption:
    """Test encryption and decryption."""

    def test_encrypt_decrypt_roundtrip(self):
        """Test encryption and decryption."""
        mk = secrets.token_bytes(32)
        plaintext = b"Hello, World!"
        associated_data = b"metadata"

        ciphertext = ENCRYPT(mk, plaintext, associated_data)
        decrypted = DECRYPT(mk, ciphertext, associated_data)

        assert decrypted == plaintext
        assert ciphertext != plaintext

    def test_decrypt_wrong_key_fails(self):
        """Test decryption with wrong key fails."""
        mk1 = secrets.token_bytes(32)
        mk2 = secrets.token_bytes(32)
        plaintext = b"Secret"
        associated_data = b"metadata"

        ciphertext = ENCRYPT(mk1, plaintext, associated_data)

        with pytest.raises(ValueError):
            DECRYPT(mk2, ciphertext, associated_data)

    def test_decrypt_wrong_ad_fails(self):
        """Test decryption with wrong associated data fails."""
        mk = secrets.token_bytes(32)
        plaintext = b"Secret"

        ciphertext = ENCRYPT(mk, plaintext, b"ad1")

        with pytest.raises(ValueError):
            DECRYPT(mk, ciphertext, b"ad2")

    def test_decrypt_tampered_ciphertext_fails(self):
        """Test decryption with tampered ciphertext fails."""
        mk = secrets.token_bytes(32)
        plaintext = b"Secret"
        associated_data = b"metadata"

        ciphertext = ENCRYPT(mk, plaintext, associated_data)
        tampered = bytearray(ciphertext)
        tampered[0] ^= 0xFF

        with pytest.raises(ValueError):
            DECRYPT(mk, bytes(tampered), associated_data)


class TestCONCAT:
    """Test CONCAT function."""

    def setup_method(self):
        self.keystore_path = "db_keys/test_concat.db"
        self.dh_keypair = x25519(keystore_path=self.keystore_path)
        self.dh_keypair.init()

    def teardown_method(self):
        if os.path.exists(self.keystore_path):
            os.remove(self.keystore_path)

    def test_concat(self):
        """Test CONCAT combines data and header."""
        ad = b"associated_data"
        header = HEADERS(dh_pair=self.dh_keypair, pn=5, n=10)

        result = CONCAT(ad, header)

        assert result.startswith(ad)
        assert len(result) == len(ad) + len(header.serialize())


class TestIntegration:
    """Integration tests."""

    def setup_method(self):
        self.keystore_path = "db_keys/test_int.db"

    def teardown_method(self):
        if os.path.exists(self.keystore_path):
            os.remove(self.keystore_path)

    def test_state_persistence(self):
        """Test state can be persisted and restored."""
        state1 = States()
        state1.DHs = GENERATE_DH(keystore_path=self.keystore_path)
        state1.RK = secrets.token_bytes(32)
        state1.DHr = secrets.token_bytes(32)
        state1.CKs = secrets.token_bytes(32)
        state1.Ns = 10
        state1.MKSKIPPED = {(b"key", 1): b"value"}

        serialized = state1.serialize()
        state2 = States.deserialize(serialized)

        assert state2.Ns == 10
        assert state2.MKSKIPPED == {(b"key", 1): b"value"}
        assert states_equal(state2, state1)
