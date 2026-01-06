"""Tests for x25519 keypair operations."""

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
    """Test keypair initialization generates valid public keys."""
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
    """Test key agreement produces matching shared secrets."""
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
    """Test key agreement rejects invalid public keys."""
    alice_db_path, _ = keypair_paths

    alice = x25519(alice_db_path)
    alice.init()

    with pytest.raises(ValueError):
        alice.agree(b"invalid_key")


def test_keypair_serialization(keypair_paths):
    """Test keypair serialization and deserialization."""
    alice_db_path, bob_db_path = keypair_paths

    alice = x25519(alice_db_path)
    bob = x25519(bob_db_path)

    alice_public_key = alice.init()
    bob_public_key = bob.init()

    alice_pnt = alice.pnt_keystore
    alice_secret = alice.secret_key

    del alice

    alice_restored = x25519(
        pnt_keystore=alice_pnt, keystore_path=alice_db_path, secret_key=alice_secret
    )

    alice_shared_key = alice_restored.agree(bob_public_key)
    bob_shared_key = bob.agree(alice_public_key)

    assert alice_shared_key == bob_shared_key
