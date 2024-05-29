"""
Tests for the x25519 key exchange mechanism.
"""

import os
import pytest
from smswithoutborders_libsig.keypairs import x25519


@pytest.fixture
def keypair_paths(tmp_path):
    alice_db_path = os.path.join(tmp_path, "alices_keys.db")
    bob_db_path = os.path.join(tmp_path, "bobs_keys.db")
    yield alice_db_path, bob_db_path
    if os.path.exists(alice_db_path):
        os.remove(alice_db_path)
    if os.path.exists(bob_db_path):
        os.remove(bob_db_path)


def test_keypair_initialization(keypair_paths):
    """Test the initialization of Alice's and Bob's public keys.

    Ensures that the public keys are not None, are of type bytes,
    and have the correct length.
    """
    alice_db_path, bob_db_path = keypair_paths

    alice = x25519(alice_db_path)
    bob = x25519(bob_db_path)

    alice_public_key = alice.init()
    bob_public_key = bob.init()

    assert alice_public_key is not None
    assert bob_public_key is not None
    assert isinstance(alice_public_key, bytes)
    assert isinstance(bob_public_key, bytes)
    assert len(alice_public_key) == 32
    assert len(bob_public_key) == 32


def test_key_agreement_protocol(keypair_paths):
    """Test the key agreement protocol between Alice and Bob.

    Verifies that the shared keys are correctly generated, are equal,
    and have the correct length.
    """
    alice_db_path, bob_db_path = keypair_paths

    alice = x25519(alice_db_path)
    bob = x25519(bob_db_path)

    alice_public_key = alice.init()
    bob_public_key = bob.init()

    alice_shared_key = alice.agree(bob_public_key)
    bob_shared_key = bob.agree(alice_public_key)

    assert alice_shared_key is not None
    assert bob_shared_key is not None
    assert isinstance(alice_shared_key, bytes)
    assert isinstance(bob_shared_key, bytes)
    assert len(alice_shared_key) == 32
    assert len(bob_shared_key) == 32
    assert alice_shared_key == bob_shared_key


def test_invalid_key_agreement(keypair_paths):
    """Test the key agreement with invalid inputs.

    Ensures that appropriate exceptions are raised for invalid inputs.
    """
    alice_db_path, bob_db_path = keypair_paths

    alice = x25519(alice_db_path)
    bob = x25519(bob_db_path)

    alice_public_key = alice.init()
    bob_public_key = bob.init()

    with pytest.raises(ValueError):
        alice.agree(b"invalid_key")

    with pytest.raises(ValueError):
        bob.agree(b"invalid_key")
