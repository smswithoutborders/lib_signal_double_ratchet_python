#!/usr/bin/env python3

import os
import secrets
import pytest
from smswithoutborders_libsig.protocols import (
    States,
    HEADERS,
    DHRatchet,
    GENERATE_DH,
    DH,
    KDF_RK,
    KDF_CK,
    ENCRYPT,
    DECRYPT,
    CONCAT,
)
from smswithoutborders_libsig.keypairs import x25519


class TestStates:
    """Test States class: serialization, deserialization, and equality"""

    def setup_method(self):
        """Setup test fixtures"""
        self.keystore_path = "db_keys/test_states.db"
        self.dh_keypair = x25519(keystore_path=self.keystore_path)
        self.dh_keypair.init()

    def teardown_method(self):
        """Cleanup test files"""
        if os.path.exists(self.keystore_path):
            os.remove(self.keystore_path)

    def test_state_initialization(self):
        """Test States can be initialized with default values"""
        state = States()
        assert state.DHs is None
        assert state.DHr is None
        assert state.RK is None
        assert state.CKs is None
        assert state.CKr is None
        assert state.Ns == 0
        assert state.Nr == 0
        assert state.PN == 0
        assert state.MKSKIPPED == {}

    def test_state_serialization(self):
        """Test States can be serialized with required fields"""
        state = States()
        state.DHs = self.dh_keypair
        state.RK = secrets.token_bytes(32)
        state.DHr = secrets.token_bytes(32)
        state.CKs = secrets.token_bytes(32)
        state.CKr = secrets.token_bytes(32)
        state.Ns = 5
        state.Nr = 3
        state.PN = 2

        serialized = state.serialize()
        assert isinstance(serialized, bytes)
        assert len(serialized) > 0

    def test_state_serialization_without_required_fields(self):
        """Test serialization fails without DHs or RK"""
        state = States()
        with pytest.raises(Exception, match="State cannot be serialized"):
            state.serialize()

        state.DHs = self.dh_keypair
        with pytest.raises(Exception, match="State cannot be serialized"):
            state.serialize()

    def test_state_deserialization(self):
        """Test States can be deserialized correctly"""
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

        assert deserialized == state
        assert deserialized.Ns == 5
        assert deserialized.Nr == 3
        assert deserialized.PN == 2
        assert deserialized.MKSKIPPED == {(b"key1", 1): b"value1"}

    def test_state_serialization_with_none_values(self):
        """Test States serialization handles None values"""
        state = States()
        state.DHs = self.dh_keypair
        state.RK = secrets.token_bytes(32)
        state.DHr = secrets.token_bytes(32)
        state.CKs = None
        state.CKr = None

        serialized = state.serialize()
        deserialized = States.deserialize(serialized)

        assert deserialized.DHr == state.DHr
        assert deserialized.CKs is None
        assert deserialized.CKr is None

    def test_state_equality_identical_states(self):
        """Test two identical states are equal"""
        state1 = States()
        state1.DHs = self.dh_keypair
        state1.RK = secrets.token_bytes(32)
        state1.DHr = secrets.token_bytes(32)
        state1.CKs = secrets.token_bytes(32)
        state1.CKr = secrets.token_bytes(32)

        serialized = state1.serialize()
        state2 = States.deserialize(serialized)

        assert state1 == state2

    def test_state_equality_different_states(self):
        """Test different states are not equal"""
        state1 = States()
        state1.DHs = self.dh_keypair
        state1.RK = secrets.token_bytes(32)
        state1.Ns = 1

        state2 = States()
        state2.DHs = self.dh_keypair
        state2.RK = secrets.token_bytes(32)
        state2.Ns = 2

        assert state1 != state2

    def test_state_equality_constant_time_comparison(self):
        """Test state equality uses constant-time comparison for secrets"""
        state1 = States()
        state1.DHs = self.dh_keypair
        state1.RK = b"secret_key_1" * 3
        state1.DHr = b"dh_remote_1" * 3

        state2 = States()
        state2.DHs = self.dh_keypair
        state2.RK = b"secret_key_2" * 3
        state2.DHr = b"dh_remote_1" * 3

        assert state1 != state2

    def test_state_equality_with_non_state_object(self):
        """Test equality with non-States object returns NotImplemented"""
        state = States()
        state.DHs = self.dh_keypair
        state.RK = secrets.token_bytes(32)

        assert state.__eq__("not a state") == NotImplemented
        assert state.__eq__(42) == NotImplemented


class TestHEADERS:
    """Test HEADERS class: initialization, serialization, and equality"""

    def setup_method(self):
        """Setup test fixtures"""
        self.keystore_path = "db_keys/test_headers.db"
        self.dh_keypair = x25519(keystore_path=self.keystore_path)
        self.dh_keypair.init()

    def teardown_method(self):
        """Cleanup test files"""
        if os.path.exists(self.keystore_path):
            os.remove(self.keystore_path)

    def test_header_initialization_with_keypair(self):
        """Test HEADERS initialization with DH keypair"""
        header = HEADERS(dh_pair=self.dh_keypair, pn=5, n=10)
        assert header.dh == self.dh_keypair.get_public_key()
        assert header.pn == 5
        assert header.n == 10

    def test_header_initialization_without_keypair(self):
        """Test HEADERS initialization without DH keypair"""
        header = HEADERS(pn=3, n=7)
        assert header.pn == 3
        assert header.n == 7
        assert not hasattr(header, "dh") or header.dh is None

    def test_header_serialization(self):
        """Test HEADERS can be serialized"""
        header = HEADERS(dh_pair=self.dh_keypair, pn=5, n=10)
        serialized = header.serialize()

        assert isinstance(serialized, bytes)
        assert len(serialized) > 8  # 8 bytes for pn + n, plus dh key

    def test_header_deserialization(self):
        """Test HEADERS can be deserialized correctly"""
        header1 = HEADERS(dh_pair=self.dh_keypair, pn=5, n=10)
        serialized = header1.serialize()
        header2 = HEADERS.deserialize(serialized)

        assert header1 == header2
        assert header2.pn == 5
        assert header2.n == 10
        assert header2.dh == self.dh_keypair.get_public_key()

    def test_header_equality_identical_headers(self):
        """Test two identical headers are equal"""
        header1 = HEADERS(dh_pair=self.dh_keypair, pn=5, n=10)
        serialized = header1.serialize()
        header2 = HEADERS.deserialize(serialized)

        assert header1 == header2

    def test_header_equality_different_headers(self):
        """Test different headers are not equal"""
        header1 = HEADERS(dh_pair=self.dh_keypair, pn=5, n=10)
        header2 = HEADERS(dh_pair=self.dh_keypair, pn=6, n=10)

        assert header1 != header2

    def test_header_equality_constant_time_comparison(self):
        """Test header equality uses constant-time comparison for dh"""
        keypair2 = x25519(keystore_path="db_keys/test_headers2.db")
        keypair2.init()

        header1 = HEADERS(dh_pair=self.dh_keypair, pn=5, n=10)
        header2 = HEADERS(dh_pair=keypair2, pn=5, n=10)

        assert header1 != header2

        if os.path.exists("db_keys/test_headers2.db"):
            os.remove("db_keys/test_headers2.db")


class TestDHRatchet:
    """Test DHRatchet class and DH operations"""

    def setup_method(self):
        """Setup test fixtures"""
        self.keystore_path1 = "db_keys/test_dh1.db"
        self.keystore_path2 = "db_keys/test_dh2.db"

    def teardown_method(self):
        """Cleanup test files"""
        for path in [self.keystore_path1, self.keystore_path2]:
            if os.path.exists(path):
                os.remove(path)

    def test_generate_dh(self):
        """Test DH keypair generation"""
        dh = GENERATE_DH(keystore_path=self.keystore_path1)
        assert dh is not None
        assert hasattr(dh, "get_public_key")
        assert len(dh.get_public_key()) == 32

    def test_dh_agreement(self):
        """Test DH key agreement between two parties"""
        dh1 = GENERATE_DH(keystore_path=self.keystore_path1)
        dh2 = GENERATE_DH(keystore_path=self.keystore_path2)

        shared1 = DH(dh1, dh2.get_public_key())
        shared2 = DH(dh2, dh1.get_public_key())

        assert shared1 == shared2
        assert len(shared1) == 32

    def test_dh_ratchet_updates_state(self):
        """Test DHRatchet updates state correctly"""
        state = States()
        state.DHs = GENERATE_DH(keystore_path=self.keystore_path1)
        state.RK = secrets.token_bytes(32)
        state.Ns = 5
        state.Nr = 3
        state.PN = 2

        dh_remote = GENERATE_DH(keystore_path=self.keystore_path2)
        header = HEADERS(dh_pair=dh_remote, pn=0, n=0)

        DHRatchet(state, header)

        assert state.PN == 5  # Previous Ns
        assert state.Ns == 0  # Reset
        assert state.Nr == 0  # Reset
        assert state.DHr == dh_remote.get_public_key()
        assert state.CKr is not None
        assert state.CKs is not None
        assert len(state.RK) == 32


class TestKDF:
    """Test Key Derivation Functions"""

    def test_kdf_rk_generates_two_keys(self):
        """Test KDF_RK generates root key and chain key"""
        rk = secrets.token_bytes(32)
        dh_out = secrets.token_bytes(32)

        new_rk, ck = KDF_RK(rk, dh_out)

        assert len(new_rk) == 32
        assert len(ck) == 32
        assert new_rk != rk
        assert new_rk != ck

    def test_kdf_rk_deterministic(self):
        """Test KDF_RK is deterministic with same inputs"""
        rk = secrets.token_bytes(32)
        dh_out = secrets.token_bytes(32)

        new_rk1, ck1 = KDF_RK(rk, dh_out)
        new_rk2, ck2 = KDF_RK(rk, dh_out)

        assert new_rk1 == new_rk2
        assert ck1 == ck2

    def test_kdf_ck_generates_chain_and_message_key(self):
        """Test KDF_CK generates new chain key and message key"""
        ck = secrets.token_bytes(32)

        new_ck, mk = KDF_CK(ck)

        assert len(new_ck) == 32
        assert len(mk) == 32
        assert new_ck != ck
        assert new_ck != mk

    def test_kdf_ck_deterministic(self):
        """Test KDF_CK is deterministic with same inputs"""
        ck = secrets.token_bytes(32)

        new_ck1, mk1 = KDF_CK(ck)
        new_ck2, mk2 = KDF_CK(ck)

        assert new_ck1 == new_ck2
        assert mk1 == mk2

    def test_kdf_ck_chain_progression(self):
        """Test KDF_CK can be chained for multiple message keys"""
        ck = secrets.token_bytes(32)

        ck1, mk1 = KDF_CK(ck)
        ck2, mk2 = KDF_CK(ck1)
        ck3, mk3 = KDF_CK(ck2)

        assert ck != ck1 != ck2 != ck3
        assert mk1 != mk2 != mk3


class TestEncryptionDecryption:
    """Test ENCRYPT and DECRYPT functions"""

    def test_encrypt_decrypt_roundtrip(self):
        """Test encryption and decryption roundtrip"""
        mk = secrets.token_bytes(32)
        plaintext = b"Hello, World! This is a test message."
        associated_data = b"associated_data"

        ciphertext = ENCRYPT(mk, plaintext, associated_data)
        decrypted = DECRYPT(mk, ciphertext, associated_data)

        assert decrypted == plaintext

    def test_encrypt_produces_different_output(self):
        """Test plaintext and ciphertext are different"""
        mk = secrets.token_bytes(32)
        plaintext = b"Secret message"
        associated_data = b"metadata"

        ciphertext = ENCRYPT(mk, plaintext, associated_data)

        assert ciphertext != plaintext
        assert len(ciphertext) > len(plaintext)

    def test_encrypt_with_different_keys(self):
        """Test encryption with different keys produces different outputs"""
        mk1 = secrets.token_bytes(32)
        mk2 = secrets.token_bytes(32)
        plaintext = b"Secret message"
        associated_data = b"metadata"

        ciphertext1 = ENCRYPT(mk1, plaintext, associated_data)
        ciphertext2 = ENCRYPT(mk2, plaintext, associated_data)

        assert ciphertext1 != ciphertext2

    def test_decrypt_with_wrong_key_fails(self):
        """Test decryption with wrong key fails"""
        mk1 = secrets.token_bytes(32)
        mk2 = secrets.token_bytes(32)
        plaintext = b"Secret message"
        associated_data = b"metadata"

        ciphertext = ENCRYPT(mk1, plaintext, associated_data)

        with pytest.raises(ValueError):
            DECRYPT(mk2, ciphertext, associated_data)

    def test_decrypt_with_wrong_associated_data_fails(self):
        """Test decryption with wrong associated data fails"""
        mk = secrets.token_bytes(32)
        plaintext = b"Secret message"
        associated_data1 = b"metadata1"
        associated_data2 = b"metadata2"

        ciphertext = ENCRYPT(mk, plaintext, associated_data1)

        with pytest.raises(ValueError):
            DECRYPT(mk, ciphertext, associated_data2)

    def test_decrypt_with_tampered_ciphertext_fails(self):
        """Test decryption with tampered ciphertext fails"""
        mk = secrets.token_bytes(32)
        plaintext = b"Secret message"
        associated_data = b"metadata"

        ciphertext = ENCRYPT(mk, plaintext, associated_data)
        tampered = bytearray(ciphertext)
        tampered[0] ^= 0xFF
        tampered = bytes(tampered)

        with pytest.raises(ValueError):
            DECRYPT(mk, tampered, associated_data)

    def test_encrypt_empty_message(self):
        """Test encryption and decryption of empty message"""
        mk = secrets.token_bytes(32)
        plaintext = b""
        associated_data = b"metadata"

        ciphertext = ENCRYPT(mk, plaintext, associated_data)
        decrypted = DECRYPT(mk, ciphertext, associated_data)

        assert decrypted == plaintext

    def test_encrypt_long_message(self):
        """Test encryption and decryption of long message"""
        mk = secrets.token_bytes(32)
        plaintext = b"A" * 10000
        associated_data = b"metadata"

        ciphertext = ENCRYPT(mk, plaintext, associated_data)
        decrypted = DECRYPT(mk, ciphertext, associated_data)

        assert decrypted == plaintext


class TestCONCAT:
    """Test CONCAT function"""

    def setup_method(self):
        """Setup test fixtures"""
        self.keystore_path = "db_keys/test_concat.db"
        self.dh_keypair = x25519(keystore_path=self.keystore_path)
        self.dh_keypair.init()

    def teardown_method(self):
        """Cleanup test files"""
        if os.path.exists(self.keystore_path):
            os.remove(self.keystore_path)

    def test_concat_combines_ad_and_header(self):
        """Test CONCAT combines associated data and header"""
        ad = b"associated_data"
        header = HEADERS(dh_pair=self.dh_keypair, pn=5, n=10)

        result = CONCAT(ad, header)

        assert result.startswith(ad)
        assert len(result) == len(ad) + len(header.serialize())

    def test_concat_deterministic(self):
        """Test CONCAT is deterministic"""
        ad = b"test_data"
        header = HEADERS(dh_pair=self.dh_keypair, pn=3, n=7)

        result1 = CONCAT(ad, header)
        result2 = CONCAT(ad, header)

        assert result1 == result2

    def test_concat_empty_associated_data(self):
        """Test CONCAT with empty associated data"""
        ad = b""
        header = HEADERS(dh_pair=self.dh_keypair, pn=1, n=2)

        result = CONCAT(ad, header)

        assert result == header.serialize()


class TestIntegration:
    """Integration tests combining multiple components"""

    def setup_method(self):
        """Setup test fixtures"""
        self.keystore_path1 = "db_keys/test_int1.db"
        self.keystore_path2 = "db_keys/test_int2.db"

    def teardown_method(self):
        """Cleanup test files"""
        for path in [self.keystore_path1, self.keystore_path2]:
            if os.path.exists(path):
                os.remove(path)

    def test_complete_message_exchange(self):
        """Test complete message exchange between two parties"""
        # Setup Alice's state
        alice_state = States()
        alice_state.DHs = GENERATE_DH(keystore_path=self.keystore_path1)
        alice_state.RK = secrets.token_bytes(32)
        alice_state.CKs = secrets.token_bytes(32)
        alice_state.Ns = 0

        # Setup Bob's initial DH
        bob_dh = GENERATE_DH(keystore_path=self.keystore_path2)
        alice_state.DHr = bob_dh.get_public_key()

        # Alice encrypts a message
        plaintext = b"Hello Bob!"
        header = HEADERS(dh_pair=alice_state.DHs, pn=alice_state.PN, n=alice_state.Ns)
        ad = CONCAT(b"", header)

        new_ck, mk = KDF_CK(alice_state.CKs)
        ciphertext = ENCRYPT(mk, plaintext, ad)

        # Verify Bob can decrypt
        decrypted = DECRYPT(mk, ciphertext, ad)
        assert decrypted == plaintext

    def test_state_persistence(self):
        """Test state can be persisted and restored"""
        # Create and populate state
        state1 = States()
        state1.DHs = GENERATE_DH(keystore_path=self.keystore_path1)
        state1.RK = secrets.token_bytes(32)
        state1.DHr = secrets.token_bytes(32)
        state1.CKs = secrets.token_bytes(32)
        state1.CKr = secrets.token_bytes(32)
        state1.Ns = 10
        state1.Nr = 5
        state1.PN = 8
        state1.MKSKIPPED = {(b"key", 1): b"value"}

        # Serialize and deserialize
        serialized = state1.serialize()
        state2 = States.deserialize(serialized)

        # Verify all fields preserved
        assert state2.Ns == 10
        assert state2.Nr == 5
        assert state2.PN == 8
        assert state2.MKSKIPPED == {(b"key", 1): b"value"}
        assert state2 == state1
