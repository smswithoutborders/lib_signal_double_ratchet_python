"""Test backward compatibility for state deserialization."""

import json
import base64
import os
import secrets

import pytest

from smswithoutborders_libsig.keypairs import x25519
from smswithoutborders_libsig.protocols import States


class TestBackwardCompatibility:
    """Test deserialization of states created before header encryption support."""

    def setup_method(self):
        """Setup test fixtures"""
        self.keystore_path = "db_keys/test_backward_compat.db"
        self.dhrs_keystore_path = "db_keys/test_backward_compat_dhrs.db"
        self.dh_keypair = x25519(keystore_path=self.keystore_path)
        self.dh_keypair.init()

    def teardown_method(self):
        """Cleanup test files"""
        if os.path.exists(self.keystore_path):
            os.remove(self.keystore_path)
        if os.path.exists(self.dhrs_keystore_path):
            os.remove(self.dhrs_keystore_path)

    def test_deserialize_state_without_header_encryption_fields(self):
        """Test deserializing a state that doesn't have header encryption fields"""
        # Create a state as it would have been serialized before header encryption support
        state_dict = {
            "version": 1,
            "DHs": base64.b64encode(self.dh_keypair.serialize()).decode("ascii"),
            "DHr": base64.b64encode(secrets.token_bytes(32)).decode("ascii"),
            "RK": base64.b64encode(secrets.token_bytes(32)).decode("ascii"),
            "CKs": base64.b64encode(secrets.token_bytes(32)).decode("ascii"),
            "CKr": base64.b64encode(secrets.token_bytes(32)).decode("ascii"),
            "Ns": 5,
            "Nr": 3,
            "PN": 2,
            "MKSKIPPED": {},
            # Note: No DHRs, DHRr, HKs, HKr, NHKs, NHKr fields
        }

        serialized = json.dumps(state_dict).encode("utf-8")

        # This should not raise a KeyError
        state = States.deserialize_json(serialized)

        # Verify basic fields are loaded
        assert state.Ns == 5
        assert state.Nr == 3
        assert state.PN == 2
        assert state.RK is not None
        assert state.CKs is not None
        assert state.CKr is not None

        # Verify header encryption fields are None
        assert state.DHRs is None
        assert state.DHRr is None
        assert state.HKs is None
        assert state.HKr is None
        assert state.NHKs is None
        assert state.NHKr is None

    def test_deserialize_state_with_partial_header_encryption_fields(self):
        """Test deserializing a state with only some header encryption fields"""
        state_dict = {
            "version": 1,
            "DHs": base64.b64encode(self.dh_keypair.serialize()).decode("ascii"),
            "DHr": base64.b64encode(secrets.token_bytes(32)).decode("ascii"),
            "RK": base64.b64encode(secrets.token_bytes(32)).decode("ascii"),
            "CKs": base64.b64encode(secrets.token_bytes(32)).decode("ascii"),
            "CKr": None,
            "Ns": 10,
            "Nr": 7,
            "PN": 5,
            "MKSKIPPED": {},
            "HKs": base64.b64encode(secrets.token_bytes(32)).decode("ascii"),
            # Note: Only HKs is present, others are missing
        }

        serialized = json.dumps(state_dict).encode("utf-8")

        # This should not raise a KeyError
        state = States.deserialize_json(serialized)

        # Verify basic fields
        assert state.Ns == 10
        assert state.Nr == 7
        assert state.PN == 5

        # Verify HKs is loaded
        assert state.HKs is not None

        # Verify other header encryption fields are None
        assert state.DHRs is None
        assert state.DHRr is None
        assert state.HKr is None
        assert state.NHKs is None
        assert state.NHKr is None

    def test_deserialize_state_with_all_header_encryption_fields(self):
        """Test deserializing a state with all header encryption fields"""
        dh_rs_keypair = x25519(keystore_path=self.dhrs_keystore_path)
        dh_rs_keypair.initHE()

        state_dict = {
            "version": 1,
            "DHs": base64.b64encode(self.dh_keypair.serialize()).decode("ascii"),
            "DHr": base64.b64encode(secrets.token_bytes(32)).decode("ascii"),
            "RK": base64.b64encode(secrets.token_bytes(32)).decode("ascii"),
            "CKs": base64.b64encode(secrets.token_bytes(32)).decode("ascii"),
            "CKr": base64.b64encode(secrets.token_bytes(32)).decode("ascii"),
            "Ns": 15,
            "Nr": 12,
            "PN": 8,
            "MKSKIPPED": {},
            "DHRs": base64.b64encode(dh_rs_keypair.serialize()).decode("ascii"),
            "DHRr": base64.b64encode(secrets.token_bytes(32)).decode("ascii"),
            "HKs": base64.b64encode(secrets.token_bytes(32)).decode("ascii"),
            "HKr": base64.b64encode(secrets.token_bytes(32)).decode("ascii"),
            "NHKs": base64.b64encode(secrets.token_bytes(32)).decode("ascii"),
            "NHKr": base64.b64encode(secrets.token_bytes(32)).decode("ascii"),
        }

        serialized = json.dumps(state_dict).encode("utf-8")

        # This should work
        state = States.deserialize_json(serialized)

        # Verify all fields are loaded
        assert state.Ns == 15
        assert state.Nr == 12
        assert state.PN == 8
        assert state.DHRs is not None
        assert state.DHRr is not None
        assert state.HKs is not None
        assert state.HKr is not None
        assert state.NHKs is not None
        assert state.NHKr is not None

    def test_deserialize_state_with_mkskipped_no_header_fields(self):
        """Test deserializing a state with MKSKIPPED but no header encryption fields"""
        state_dict = {
            "version": 1,
            "DHs": base64.b64encode(self.dh_keypair.serialize()).decode("ascii"),
            "DHr": base64.b64encode(secrets.token_bytes(32)).decode("ascii"),
            "RK": base64.b64encode(secrets.token_bytes(32)).decode("ascii"),
            "CKs": base64.b64encode(secrets.token_bytes(32)).decode("ascii"),
            "CKr": base64.b64encode(secrets.token_bytes(32)).decode("ascii"),
            "Ns": 20,
            "Nr": 15,
            "PN": 10,
            "MKSKIPPED": {
                f"{base64.b64encode(b'dh_key_1' * 4).decode('ascii')}:1": base64.b64encode(
                    b"message_key_1" * 2
                ).decode("ascii"),
            },
            # Note: No header encryption fields
        }

        serialized = json.dumps(state_dict).encode("utf-8")

        # This should work
        state = States.deserialize_json(serialized)

        # Verify MKSKIPPED is loaded
        assert len(state.MKSKIPPED) == 1
        assert state.Ns == 20
        assert state.Nr == 15

        # Verify header encryption fields are None
        assert state.DHRs is None
        assert state.DHRr is None
        assert state.HKs is None
        assert state.HKr is None
        assert state.NHKs is None
        assert state.NHKr is None
