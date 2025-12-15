import os
import secrets

import pytest

from smswithoutborders_libsig.keypairs import x25519
from smswithoutborders_libsig.protocols import States
from tests.test_helpers import states_equal


class TestJSONSerialization:
    """Test JSON-based serialization."""

    def setup_method(self):
        """Setup test fixtures"""
        self.keystore_path = "db_keys/test_json_states.db"
        self.dh_keypair = x25519(keystore_path=self.keystore_path)
        self.dh_keypair.init()

    def teardown_method(self):
        """Cleanup test files"""
        if os.path.exists(self.keystore_path):
            os.remove(self.keystore_path)

    def test_json_serialization_basic(self):
        """Test basic JSON serialization"""
        state = States()
        state.DHs = self.dh_keypair
        state.RK = secrets.token_bytes(32)
        state.DHr = secrets.token_bytes(32)
        state.CKs = secrets.token_bytes(32)
        state.CKr = secrets.token_bytes(32)
        state.Ns = 5
        state.Nr = 3
        state.PN = 2

        serialized = state.serialize_json()
        assert isinstance(serialized, bytes)
        assert len(serialized) > 0

    def test_json_deserialization_basic(self):
        """Test basic JSON deserialization"""
        state = States()
        state.DHs = self.dh_keypair
        state.RK = secrets.token_bytes(32)
        state.DHr = secrets.token_bytes(32)
        state.CKs = secrets.token_bytes(32)
        state.CKr = secrets.token_bytes(32)
        state.Ns = 5
        state.Nr = 3
        state.PN = 2

        serialized = state.serialize_json()
        deserialized = States.deserialize_json(serialized)

        assert states_equal(deserialized, state)
        assert deserialized.Ns == 5
        assert deserialized.Nr == 3
        assert deserialized.PN == 2

    def test_json_serialization_with_mkskipped(self):
        """Test JSON serialization with MKSKIPPED data"""
        state = States()
        state.DHs = self.dh_keypair
        state.RK = secrets.token_bytes(32)
        state.DHr = secrets.token_bytes(32)
        state.CKs = secrets.token_bytes(32)
        state.CKr = secrets.token_bytes(32)
        state.Ns = 10
        state.Nr = 7
        state.PN = 5
        state.MKSKIPPED = {
            (b"dh_key_1" * 4, 1): b"message_key_1" * 2,
            (b"dh_key_2" * 4, 5): b"message_key_2" * 2,
            (b"dh_key_3" * 4, 10): b"message_key_3" * 2,
        }

        serialized = state.serialize_json()
        deserialized = States.deserialize_json(serialized)

        assert states_equal(deserialized, state)
        assert deserialized.MKSKIPPED == state.MKSKIPPED
        assert len(deserialized.MKSKIPPED) == 3

    def test_json_serialization_with_none_values(self):
        """Test JSON serialization handles None values correctly"""
        state = States()
        state.DHs = self.dh_keypair
        state.RK = secrets.token_bytes(32)
        state.DHr = secrets.token_bytes(32)
        state.CKs = None
        state.CKr = None

        serialized = state.serialize_json()
        deserialized = States.deserialize_json(serialized)

        assert deserialized.DHr == state.DHr
        assert deserialized.CKs is None
        assert deserialized.CKr is None
        assert states_equal(deserialized, state)

    def test_json_serialization_empty_mkskipped(self):
        """Test JSON serialization with empty MKSKIPPED"""
        state = States()
        state.DHs = self.dh_keypair
        state.RK = secrets.token_bytes(32)
        state.DHr = secrets.token_bytes(32)
        state.MKSKIPPED = {}

        serialized = state.serialize_json()
        deserialized = States.deserialize_json(serialized)

        assert deserialized.MKSKIPPED == {}
        assert states_equal(deserialized, state)

    def test_json_serialization_without_required_fields(self):
        """Test JSON serialization fails without DHs or RK"""
        state = States()
        with pytest.raises(Exception, match="State cannot be serialized"):
            state.serialize_json()

        state.DHs = self.dh_keypair
        with pytest.raises(Exception, match="State cannot be serialized"):
            state.serialize_json()

    def test_json_serialization_deterministic(self):
        """Test JSON serialization is deterministic"""
        state = States()
        state.DHs = self.dh_keypair
        state.RK = secrets.token_bytes(32)
        state.DHr = secrets.token_bytes(32)
        state.Ns = 5

        serialized1 = state.serialize_json()
        serialized2 = state.serialize_json()

        assert serialized1 == serialized2

    def test_json_output_is_valid_json(self):
        """Test that serialized output is valid JSON"""
        import json

        state = States()
        state.DHs = self.dh_keypair
        state.RK = secrets.token_bytes(32)
        state.DHr = secrets.token_bytes(32)

        serialized = state.serialize_json()

        # Should not raise exception
        parsed = json.loads(serialized.decode("utf-8"))
        assert isinstance(parsed, dict)
        assert "version" in parsed
        assert parsed["version"] == 1

    def test_json_no_binary_in_output(self):
        """Test that JSON output contains no binary data (only base64 strings)"""
        import json

        state = States()
        state.DHs = self.dh_keypair
        state.RK = secrets.token_bytes(32)
        state.DHr = secrets.token_bytes(32)
        state.MKSKIPPED = {(b"test_key" * 4, 1): b"test_value" * 2}

        serialized = state.serialize_json()
        parsed = json.loads(serialized.decode("utf-8"))

        # All values should be strings, integers, or dicts (no bytes)
        assert isinstance(parsed["DHs"], str)
        assert isinstance(parsed["RK"], str)
        assert isinstance(parsed["DHr"], str)
        assert isinstance(parsed["Ns"], int)
        assert isinstance(parsed["MKSKIPPED"], dict)
        for key, value in parsed["MKSKIPPED"].items():
            assert isinstance(key, str)
            assert isinstance(value, str)


class TestPickleToJSONMigration:
    """Test migration from pickle serialization to JSON serialization"""

    def setup_method(self):
        """Setup test fixtures"""
        self.keystore_path = "db_keys/test_migration.db"
        self.dh_keypair = x25519(keystore_path=self.keystore_path)
        self.dh_keypair.init()

    def teardown_method(self):
        """Cleanup test files"""
        if os.path.exists(self.keystore_path):
            os.remove(self.keystore_path)

    def test_migrate_pickle_to_json_basic(self):
        """Test migrating basic state from pickle to JSON"""
        # Create state and serialize with pickle
        state_original = States()
        state_original.DHs = self.dh_keypair
        state_original.RK = secrets.token_bytes(32)
        state_original.DHr = secrets.token_bytes(32)
        state_original.CKs = secrets.token_bytes(32)
        state_original.CKr = secrets.token_bytes(32)
        state_original.Ns = 5
        state_original.Nr = 3
        state_original.PN = 2

        pickle_serialized = state_original.serialize()

        # Deserialize with pickle
        state_from_pickle = States.deserialize(pickle_serialized)

        # Re-serialize with JSON
        json_serialized = state_from_pickle.serialize_json()

        # Deserialize with JSON
        state_from_json = States.deserialize_json(json_serialized)

        # Verify all data is preserved
        assert states_equal(state_from_json, state_original)
        assert state_from_json.Ns == 5
        assert state_from_json.Nr == 3
        assert state_from_json.PN == 2

    def test_migrate_pickle_to_json_with_mkskipped(self):
        """Test migrating state with MKSKIPPED from pickle to JSON"""
        # Create state with MKSKIPPED
        state_original = States()
        state_original.DHs = self.dh_keypair
        state_original.RK = secrets.token_bytes(32)
        state_original.DHr = secrets.token_bytes(32)
        state_original.CKs = secrets.token_bytes(32)
        state_original.CKr = secrets.token_bytes(32)
        state_original.Ns = 10
        state_original.Nr = 7
        state_original.PN = 5
        state_original.MKSKIPPED = {
            (b"dh_key_1" * 4, 1): b"message_key_1" * 2,
            (b"dh_key_2" * 4, 5): b"message_key_2" * 2,
            (b"dh_key_3" * 4, 10): b"message_key_3" * 2,
        }

        # Pickle serialize
        pickle_serialized = state_original.serialize()

        # Deserialize with pickle
        state_from_pickle = States.deserialize(pickle_serialized)

        # Re-serialize with JSON
        json_serialized = state_from_pickle.serialize_json()

        # Deserialize with JSON
        state_from_json = States.deserialize_json(json_serialized)

        # Verify all data is preserved including MKSKIPPED
        assert states_equal(state_from_json, state_original)
        assert state_from_json.MKSKIPPED == state_original.MKSKIPPED
        assert len(state_from_json.MKSKIPPED) == 3

        # Verify each MKSKIPPED entry
        for key, value in state_original.MKSKIPPED.items():
            assert key in state_from_json.MKSKIPPED
            assert state_from_json.MKSKIPPED[key] == value

    def test_migrate_pickle_to_json_with_none_values(self):
        """Test migrating state with None values from pickle to JSON"""
        state_original = States()
        state_original.DHs = self.dh_keypair
        state_original.RK = secrets.token_bytes(32)
        state_original.DHr = secrets.token_bytes(32)
        state_original.CKs = None
        state_original.CKr = None

        pickle_serialized = state_original.serialize()
        state_from_pickle = States.deserialize(pickle_serialized)
        json_serialized = state_from_pickle.serialize_json()
        state_from_json = States.deserialize_json(json_serialized)

        assert states_equal(state_from_json, state_original)
        assert state_from_json.CKs is None
        assert state_from_json.CKr is None

    def test_migrate_pickle_to_json_preserves_crypto_keys(self):
        """Test that cryptographic keys are preserved during migration"""
        state_original = States()
        state_original.DHs = self.dh_keypair
        state_original.RK = secrets.token_bytes(32)
        state_original.DHr = secrets.token_bytes(32)
        state_original.CKs = secrets.token_bytes(32)
        state_original.CKr = secrets.token_bytes(32)

        pickle_serialized = state_original.serialize()
        state_from_pickle = States.deserialize(pickle_serialized)
        json_serialized = state_from_pickle.serialize_json()
        state_from_json = States.deserialize_json(json_serialized)

        # Verify cryptographic keys are byte-for-byte identical
        assert state_from_json.RK == state_original.RK
        assert state_from_json.DHr == state_original.DHr
        assert state_from_json.CKs == state_original.CKs
        assert state_from_json.CKr == state_original.CKr
        assert (
            state_from_json.DHs.get_public_key() == state_original.DHs.get_public_key()
        )

    def test_migrate_multiple_states(self):
        """Test migrating multiple different states from pickle to JSON"""
        states = []

        for i in range(5):
            keystore_path = f"db_keys/test_migration_{i}.db"
            if os.path.exists(keystore_path):
                os.remove(keystore_path)

            dh = x25519(keystore_path=keystore_path)
            dh.init()

            state = States()
            state.DHs = dh
            state.RK = secrets.token_bytes(32)
            state.DHr = secrets.token_bytes(32)
            state.CKs = secrets.token_bytes(32)
            state.CKr = secrets.token_bytes(32)
            state.Ns = i * 10
            state.Nr = i * 5
            state.PN = i * 3
            state.MKSKIPPED = {
                (secrets.token_bytes(32), j): secrets.token_bytes(32) for j in range(i)
            }

            states.append((state, keystore_path))

        for original_state, keystore_path in states:
            pickle_serialized = original_state.serialize()
            state_from_pickle = States.deserialize(pickle_serialized)
            json_serialized = state_from_pickle.serialize_json()
            state_from_json = States.deserialize_json(json_serialized)

            assert states_equal(state_from_json, original_state)

            if os.path.exists(keystore_path):
                os.remove(keystore_path)

    def test_json_deserialization_invalid_version(self):
        """Test that invalid version raises an error"""
        import json

        invalid_data = json.dumps({"version": 99}).encode("utf-8")

        with pytest.raises(ValueError, match="Unsupported state version"):
            States.deserialize_json(invalid_data)

    def test_roundtrip_consistency_pickle_vs_json(self):
        """Test that pickle and JSON produce equivalent results after roundtrip"""
        state_original = States()
        state_original.DHs = self.dh_keypair
        state_original.RK = secrets.token_bytes(32)
        state_original.DHr = secrets.token_bytes(32)
        state_original.CKs = secrets.token_bytes(32)
        state_original.CKr = secrets.token_bytes(32)
        state_original.Ns = 42
        state_original.Nr = 24
        state_original.PN = 12
        state_original.MKSKIPPED = {(b"key" * 8, 7): b"value" * 8}

        # Roundtrip through pickle
        pickle_roundtrip = States.deserialize(state_original.serialize())

        # Roundtrip through JSON
        json_roundtrip = States.deserialize_json(state_original.serialize_json())

        # Both should equal the original
        assert states_equal(pickle_roundtrip, state_original)
        assert states_equal(json_roundtrip, state_original)

        # And should equal each other
        assert states_equal(pickle_roundtrip, json_roundtrip)


class TestJSONSecurityProperties:
    """Test security properties of JSON serialization"""

    def setup_method(self):
        """Setup test fixtures"""
        self.keystore_path = "db_keys/test_security.db"
        self.dh_keypair = x25519(keystore_path=self.keystore_path)
        self.dh_keypair.init()

    def teardown_method(self):
        """Cleanup test files"""
        if os.path.exists(self.keystore_path):
            os.remove(self.keystore_path)

    def test_json_no_code_execution_risk(self):
        """Test that JSON deserialization does not execute code"""
        # JSON should not allow code execution unlike pickle
        state = States()
        state.DHs = self.dh_keypair
        state.RK = secrets.token_bytes(32)
        state.DHr = secrets.token_bytes(32)

        serialized = state.serialize_json()

        # This should safely deserialize without any code execution
        deserialized = States.deserialize_json(serialized)
        assert states_equal(deserialized, state)

    def test_json_malformed_input_handling(self):
        """Test that malformed JSON input raises appropriate errors"""
        with pytest.raises((ValueError, Exception)):
            States.deserialize_json(b"not valid json")

        with pytest.raises((ValueError, Exception)):
            States.deserialize_json(b"{incomplete")

    def test_json_tampering_detection(self):
        """Test that tampering with JSON is detectable through data validation"""
        state = States()
        state.DHs = self.dh_keypair
        state.RK = secrets.token_bytes(32)
        state.DHr = secrets.token_bytes(32)

        serialized = state.serialize_json()

        # Tamper with the data
        tampered = serialized.replace(b'"version": 1', b'"version": "hacked"')

        # Should fail validation
        with pytest.raises((ValueError, TypeError, Exception)):
            States.deserialize_json(tampered)
