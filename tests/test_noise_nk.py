"""Tests for Noise NK handshake implementation."""

import secrets
import tempfile
import os
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from smswithoutborders_libsig.keypairs import x25519


class TestNoiseNKHandshake:
    """Noise NK pattern tests."""

    def test_derive_same_keys(self):
        """Both parties derive identical RK0, HK, NHK"""
        client_nonce = secrets.token_bytes(16)
        server_nonce = secrets.token_bytes(16)

        SI = X25519PrivateKey.generate()
        SI_pk = SI.public_key().public_bytes_raw()

        eS = X25519PrivateKey.generate()
        eS_pk = eS.public_key().public_bytes_raw()

        eC = X25519PrivateKey.generate()
        eC_pk = eC.public_key().public_bytes_raw()

        client_RK0, client_HK, client_NHK = x25519().agreeWithNoiseNKPattern(
            client_nonce=client_nonce,
            server_nonce=server_nonce,
            eC=eC,
            SI_pk=SI_pk,
            eS_pk=eS_pk,
        )

        server_RK0, server_HK, server_NHK = x25519().agreeWithNoiseNKPattern(
            client_nonce=client_nonce,
            server_nonce=server_nonce,
            eC_pk=eC_pk,
            SI=SI,
            eS=eS,
        )

        assert client_RK0 == server_RK0
        assert client_HK == server_HK
        assert client_NHK == server_NHK

    def test_key_lengths(self):
        """Verify all keys are 32 bytes"""
        client_nonce = secrets.token_bytes(16)
        server_nonce = secrets.token_bytes(16)

        SI = X25519PrivateKey.generate()
        SI_pk = SI.public_key().public_bytes_raw()

        eS = X25519PrivateKey.generate()
        eS_pk = eS.public_key().public_bytes_raw()

        eC = X25519PrivateKey.generate()

        RK0, HK, NHK = x25519().agreeWithNoiseNKPattern(
            client_nonce=client_nonce,
            server_nonce=server_nonce,
            eC=eC,
            SI_pk=SI_pk,
            eS_pk=eS_pk,
        )

        assert len(RK0) == 32
        assert len(HK) == 32
        assert len(NHK) == 32

    def test_client_loads_eC_from_self(self):
        """Client loads eC from self when not provided"""
        client_nonce = secrets.token_bytes(16)
        server_nonce = secrets.token_bytes(16)

        SI = X25519PrivateKey.generate()
        SI_pk = SI.public_key().public_bytes_raw()

        eS = X25519PrivateKey.generate()
        eS_pk = eS.public_key().public_bytes_raw()

        with tempfile.TemporaryDirectory() as tmpdir:
            client = x25519()
            client.keystore_path = os.path.join(tmpdir, "client.db")
            client.init()

            RK0, HK, NHK = client.agreeWithNoiseNKPattern(
                client_nonce=client_nonce,
                server_nonce=server_nonce,
                SI_pk=SI_pk,
                eS_pk=eS_pk,
            )

            assert len(RK0) == 32
            assert len(HK) == 32
            assert len(NHK) == 32

    def test_server_loads_eS_from_self(self):
        """Server loads eS from self when not provided"""
        client_nonce = secrets.token_bytes(16)
        server_nonce = secrets.token_bytes(16)

        SI = X25519PrivateKey.generate()

        eC = X25519PrivateKey.generate()
        eC_pk = eC.public_key().public_bytes_raw()

        with tempfile.TemporaryDirectory() as tmpdir:
            server = x25519()
            server.keystore_path = os.path.join(tmpdir, "server.db")
            server.init()

            RK0, HK, NHK = server.agreeWithNoiseNKPattern(
                client_nonce=client_nonce,
                server_nonce=server_nonce,
                eC_pk=eC_pk,
                SI=SI,
            )

            assert len(RK0) == 32
            assert len(HK) == 32
            assert len(NHK) == 32
