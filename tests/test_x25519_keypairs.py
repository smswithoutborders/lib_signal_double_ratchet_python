"""Tests for x25519 keypair operations."""

import os
import secrets

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

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
    """Test basic agreeWithAuthAndNonce with bidirectional key exchange.

    Client-side derivation:
    - Client DH1 = DH(eC, SI_pk)
    - Client DH2 = DH(eC, eS_pk)

    Server-side derivation:
    - Server DH1 = DH(SI, eC_pk)
    - Server DH2 = DH(eS, eC_pk)
    """
    # Client keys
    client_eph_db = os.path.join(tmp_path, "client_eph.db")
    client_eph = x25519(client_eph_db)
    client_eph_public = client_eph.init()
    client_eph_private = client_eph.load_keystore(
        client_eph.pnt_keystore, client_eph.secret_key
    )

    # Server keys
    server_identity_db = os.path.join(tmp_path, "server_identity.db")
    server_identity = x25519(server_identity_db)
    server_identity_public = server_identity.init()
    server_identity_private = server_identity.load_keystore(
        server_identity.pnt_keystore, server_identity.secret_key
    )

    server_eph_db = os.path.join(tmp_path, "server_eph.db")
    server_eph = x25519(server_eph_db)
    server_eph_public = server_eph.init()

    # Nonces
    client_nonce = secrets.token_bytes(16)
    server_nonce = secrets.token_bytes(16)

    # Client-side derivation
    handshake_salt = client_nonce + server_nonce
    salt = b"RelaySMS v1"
    info = b"RelaySMS C2S DR v1"

    # Client DH computations
    client_dh1 = client_eph_private.exchange(
        X25519PublicKey.from_public_bytes(server_identity_public)
    )
    client_dh2 = client_eph_private.exchange(
        X25519PublicKey.from_public_bytes(server_eph_public)
    )

    # Client key derivation chain
    client_ck = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=info,
    ).derive(handshake_salt)

    client_ck = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=client_ck,
        info=info,
    ).derive(client_dh1)

    client_shared = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=client_ck,
        info=info,
    ).derive(client_dh2)

    # Server-side derivation
    server_shared = server_eph.agreeWithAuthAndNonce(
        server_identity_private, client_eph_public, client_nonce, server_nonce
    )

    assert client_shared is not None
    assert server_shared is not None
    assert isinstance(client_shared, bytes)
    assert isinstance(server_shared, bytes)
    assert len(client_shared) == 32
    assert len(server_shared) == 32
    assert client_shared == server_shared


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
