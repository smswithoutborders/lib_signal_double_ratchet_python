"""Tests for x25519 keypair operations."""

import os
import secrets

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


def test_agree_with_auth_and_nonce_basic(tmp_path):
    """Test basic agreeWithAuthAndNonce with bidirectional key exchange."""
    alice_auth_db = os.path.join(tmp_path, "alice_auth.db")
    alice_eph_db = os.path.join(tmp_path, "alice_eph.db")
    bob_static_db = os.path.join(tmp_path, "bob_static.db")
    bob_eph_db = os.path.join(tmp_path, "bob_eph.db")

    alice_auth = x25519(alice_auth_db)
    _ = alice_auth.init()
    alice_auth_private = alice_auth.load_keystore(
        alice_auth.pnt_keystore, alice_auth.secret_key
    )

    alice_eph = x25519(alice_eph_db)
    alice_eph_public = alice_eph.init()
    _ = alice_eph.load_keystore(alice_eph.pnt_keystore, alice_eph.secret_key)

    bob_static = x25519(bob_static_db)
    _ = bob_static.init()
    bob_static_private = bob_static.load_keystore(
        bob_static.pnt_keystore, bob_static.secret_key
    )

    bob_eph = x25519(bob_eph_db)
    bob_eph_public = bob_eph.init()
    _ = bob_eph.load_keystore(bob_eph.pnt_keystore, bob_eph.secret_key)

    nonce1 = secrets.token_bytes(16)
    nonce2 = secrets.token_bytes(16)

    alice_shared = alice_eph.agreeWithAuthAndNonce(
        alice_auth_private, bob_eph_public, nonce1, nonce2
    )

    bob_shared = bob_eph.agreeWithAuthAndNonce(
        bob_static_private, alice_eph_public, nonce1, nonce2
    )

    assert alice_shared is not None
    assert bob_shared is not None
    assert isinstance(alice_shared, bytes)
    assert isinstance(bob_shared, bytes)
    assert len(alice_shared) == 32
    assert len(bob_shared) == 32


def test_agree_with_auth_and_nonce_deterministic(tmp_path):
    """Test that same inputs produce same output for both parties."""
    alice_auth_db = os.path.join(tmp_path, "alice_auth.db")
    alice_eph_db = os.path.join(tmp_path, "alice_eph.db")
    bob_static_db = os.path.join(tmp_path, "bob_static.db")
    bob_eph_db = os.path.join(tmp_path, "bob_eph.db")

    alice_auth = x25519(alice_auth_db)
    alice_auth.init()
    alice_auth_private = alice_auth.load_keystore(
        alice_auth.pnt_keystore, alice_auth.secret_key
    )

    alice_eph = x25519(alice_eph_db)
    alice_eph.init()

    bob_static = x25519(bob_static_db)
    bob_static.init()
    _ = bob_static.load_keystore(bob_static.pnt_keystore, bob_static.secret_key)

    bob_eph = x25519(bob_eph_db)
    bob_eph_public = bob_eph.init()

    nonce1 = secrets.token_bytes(16)
    nonce2 = secrets.token_bytes(16)

    secret1 = alice_eph.agreeWithAuthAndNonce(
        alice_auth_private, bob_eph_public, nonce1, nonce2
    )
    secret2 = alice_eph.agreeWithAuthAndNonce(
        alice_auth_private, bob_eph_public, nonce1, nonce2
    )

    assert secret1 == secret2


def test_agree_with_auth_and_nonce_different_nonces(tmp_path):
    """Test that different nonces produce different secrets."""
    alice_auth_db = os.path.join(tmp_path, "alice_auth.db")
    alice_eph_db = os.path.join(tmp_path, "alice_eph.db")
    bob_eph_db = os.path.join(tmp_path, "bob_eph.db")

    alice_auth = x25519(alice_auth_db)
    alice_auth.init()
    alice_auth_private = alice_auth.load_keystore(
        alice_auth.pnt_keystore, alice_auth.secret_key
    )

    alice_eph = x25519(alice_eph_db)
    alice_eph.init()

    bob_eph = x25519(bob_eph_db)
    bob_eph_public = bob_eph.init()

    nonce1a = secrets.token_bytes(16)
    nonce2a = secrets.token_bytes(16)
    nonce1b = secrets.token_bytes(16)
    nonce2b = secrets.token_bytes(16)

    secret_a = alice_eph.agreeWithAuthAndNonce(
        alice_auth_private, bob_eph_public, nonce1a, nonce2a
    )
    secret_b = alice_eph.agreeWithAuthAndNonce(
        alice_auth_private, bob_eph_public, nonce1b, nonce2b
    )

    assert secret_a != secret_b


def test_agree_with_auth_and_nonce_custom_salt_info(tmp_path):
    """Test agreeWithAuthAndNonce with custom salt and info parameters."""
    alice_auth_db = os.path.join(tmp_path, "alice_auth.db")
    alice_eph_db = os.path.join(tmp_path, "alice_eph.db")
    bob_eph_db = os.path.join(tmp_path, "bob_eph.db")

    alice_auth = x25519(alice_auth_db)
    alice_auth.init()
    alice_auth_private = alice_auth.load_keystore(
        alice_auth.pnt_keystore, alice_auth.secret_key
    )

    alice_eph = x25519(alice_eph_db)
    alice_eph.init()

    bob_eph = x25519(bob_eph_db)
    bob_eph_public = bob_eph.init()

    nonce1 = secrets.token_bytes(16)
    nonce2 = secrets.token_bytes(16)

    secret_default = alice_eph.agreeWithAuthAndNonce(
        alice_auth_private, bob_eph_public, nonce1, nonce2
    )
    secret_custom = alice_eph.agreeWithAuthAndNonce(
        alice_auth_private,
        bob_eph_public,
        nonce1,
        nonce2,
        salt=b"CustomSalt",
        info=b"CustomInfo",
    )

    assert secret_default != secret_custom
