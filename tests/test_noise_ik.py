"""Tests for Noise IK handshake implementation using X25519 keys."""

import tempfile
import os
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from smswithoutborders_libsig.keypairs import x25519


class TestNoiseIKMessage1:
    """Noise IK Message 1."""

    def test_derive_same_keys(self):
        """Both parties derive identical RK0, HK, NHK, CK"""
        server_static_sk = X25519PrivateKey.generate()
        client_static_sk = X25519PrivateKey.generate()

        with tempfile.TemporaryDirectory() as tmpdir:
            client = x25519()
            client.keystore_path = os.path.join(tmpdir, "client.db")
            client_eph_pk = client.init()

            client_h, client_enc_pk, client_rk0, client_hk, client_nhk, client_ck = (
                client.agreeWithNoiseIKPatternMessage1(
                    client_static_private_key=client_static_sk,
                    client_enc_static_public_key=None,
                    server_static_public_key=server_static_sk.public_key(),
                    server_static_private_key=None,
                )
            )

            server_h, _, server_rk0, server_hk, server_nhk, server_ck = (
                x25519().agreeWithNoiseIKPatternMessage1(
                    client_static_private_key=None,
                    client_enc_static_public_key=client_enc_pk,
                    server_static_public_key=None,
                    server_static_private_key=server_static_sk,
                    client_ephemeral_public_key=X25519PublicKey.from_public_bytes(
                        client_eph_pk
                    ),
                )
            )

        assert client_rk0 == server_rk0
        assert client_hk == server_hk
        assert client_nhk == server_nhk
        assert client_h == server_h
        assert client_ck == server_ck

    def test_output_lengths(self):
        """All outputs are 32 bytes"""
        server_static_sk = X25519PrivateKey.generate()
        client_static_sk = X25519PrivateKey.generate()

        with tempfile.TemporaryDirectory() as tmpdir:
            client = x25519()
            client.keystore_path = os.path.join(tmpdir, "client.db")
            client.init()

            h, enc_pk, rk0, hk, nhk, ck = client.agreeWithNoiseIKPatternMessage1(
                client_static_private_key=client_static_sk,
                client_enc_static_public_key=None,
                server_static_public_key=server_static_sk.public_key(),
                server_static_private_key=None,
            )

        assert len(h) == 32
        assert len(rk0) == 32
        assert len(hk) == 32
        assert len(nhk) == 32
        assert len(ck) == 32


class TestNoiseIKMessage2:
    """Noise IK Message 2."""

    def test_derive_same_keys(self):
        """Both parties derive identical RK1, HK1, NHK1"""
        server_static_sk = X25519PrivateKey.generate()
        client_static_sk = X25519PrivateKey.generate()

        with tempfile.TemporaryDirectory() as tmpdir:
            client = x25519()
            client.keystore_path = os.path.join(tmpdir, "client.db")
            client_eph_pk = client.init()

            client_h, client_enc_pk, client_rk0, _, _, client_ck = (
                client.agreeWithNoiseIKPatternMessage1(
                    client_static_private_key=client_static_sk,
                    client_enc_static_public_key=None,
                    server_static_public_key=server_static_sk.public_key(),
                    server_static_private_key=None,
                )
            )

            server_h, _, server_rk0, _, _, server_ck = (
                x25519().agreeWithNoiseIKPatternMessage1(
                    client_static_private_key=None,
                    client_enc_static_public_key=client_enc_pk,
                    server_static_public_key=None,
                    server_static_private_key=server_static_sk,
                    client_ephemeral_public_key=X25519PublicKey.from_public_bytes(
                        client_eph_pk
                    ),
                )
            )

            assert client_rk0 == server_rk0

            server_msg2 = x25519()
            server_msg2.keystore_path = os.path.join(tmpdir, "server.db")
            server_eph_pk = server_msg2.init()

            server_h2, server_eph_pk_returned, server_rk1, server_hk1, server_nhk1 = (
                server_msg2.agreeWithNoiseIKPatternMessage2(
                    client_ephemeral_public_key=X25519PublicKey.from_public_bytes(
                        client_eph_pk
                    ),
                    server_ephemeral_public_key=None,
                    server_static_public_key=None,
                    server_static_private_key=server_static_sk,
                    h=server_h,
                    ck=server_ck,
                )
            )

            assert server_eph_pk == server_eph_pk_returned

            client_h2, _, client_rk1, client_hk1, client_nhk1 = (
                client.agreeWithNoiseIKPatternMessage2(
                    client_ephemeral_public_key=None,
                    server_ephemeral_public_key=X25519PublicKey.from_public_bytes(
                        server_eph_pk
                    ),
                    server_static_public_key=server_static_sk.public_key(),
                    server_static_private_key=None,
                    h=client_h,
                    ck=client_ck,
                )
            )

            assert client_rk1 == server_rk1
            assert client_hk1 == server_hk1
            assert client_nhk1 == server_nhk1
            assert client_h2 == server_h2
            assert client_rk1 != client_rk0
            assert server_rk1 != server_rk0

    def test_output_lengths(self):
        """All outputs are 32 bytes"""
        server_static_sk = X25519PrivateKey.generate()
        client_static_sk = X25519PrivateKey.generate()

        with tempfile.TemporaryDirectory() as tmpdir:
            client = x25519()
            client.keystore_path = os.path.join(tmpdir, "client.db")
            client.init()

            h, _, _, _, _, ck = client.agreeWithNoiseIKPatternMessage1(
                client_static_private_key=client_static_sk,
                client_enc_static_public_key=None,
                server_static_public_key=server_static_sk.public_key(),
                server_static_private_key=None,
            )

            server_ephemeral_sk = X25519PrivateKey.generate()

            h2, eph_pk, rk1, hk1, nhk1 = client.agreeWithNoiseIKPatternMessage2(
                client_ephemeral_public_key=None,
                server_ephemeral_public_key=server_ephemeral_sk.public_key(),
                server_static_public_key=server_static_sk.public_key(),
                server_static_private_key=None,
                h=h,
                ck=ck,
            )

        assert len(h2) == 32
        assert len(eph_pk) == 32
        assert len(rk1) == 32
        assert len(hk1) == 32
        assert len(nhk1) == 32


class TestNoiseIKHandshake:
    """Complete handshake and Double Ratchet integration"""

    def test_full_handshake(self):
        """Server generates eS"""
        server_static_sk = X25519PrivateKey.generate()
        client_static_sk = X25519PrivateKey.generate()

        with tempfile.TemporaryDirectory() as tmpdir:
            client = x25519()
            client.keystore_path = os.path.join(tmpdir, "client.db")
            client_eph_pk = client.init()

            client_h, client_enc_pk, client_rk0, _, _, client_ck = (
                client.agreeWithNoiseIKPatternMessage1(
                    client_static_private_key=client_static_sk,
                    client_enc_static_public_key=None,
                    server_static_public_key=server_static_sk.public_key(),
                    server_static_private_key=None,
                )
            )

            server_h, _, server_rk0, _, _, server_ck = (
                x25519().agreeWithNoiseIKPatternMessage1(
                    client_static_private_key=None,
                    client_enc_static_public_key=client_enc_pk,
                    server_static_public_key=None,
                    server_static_private_key=server_static_sk,
                    client_ephemeral_public_key=X25519PublicKey.from_public_bytes(
                        client_eph_pk
                    ),
                )
            )

            assert client_rk0 == server_rk0

            server_msg2 = x25519()
            server_msg2.keystore_path = os.path.join(tmpdir, "server.db")
            server_eph_pk = server_msg2.init()

            server_h2, server_eph_pk_sent, server_rk1, _, _ = (
                server_msg2.agreeWithNoiseIKPatternMessage2(
                    client_ephemeral_public_key=X25519PublicKey.from_public_bytes(
                        client_eph_pk
                    ),
                    server_ephemeral_public_key=None,
                    server_static_public_key=None,
                    server_static_private_key=server_static_sk,
                    h=server_h,
                    ck=server_ck,
                )
            )

            client_h2, _, client_rk1, _, _ = client.agreeWithNoiseIKPatternMessage2(
                client_ephemeral_public_key=None,
                server_ephemeral_public_key=X25519PublicKey.from_public_bytes(
                    server_eph_pk_sent
                ),
                server_static_public_key=server_static_sk.public_key(),
                server_static_private_key=None,
                h=client_h,
                ck=client_ck,
            )

            assert client_rk1 == server_rk1
            assert client_h2 == server_h2
            assert client_rk1 != client_rk0

    def test_rk1_double_ratchet(self):
        from smswithoutborders_libsig import ratchetsHE, protocols

        server_static_sk = X25519PrivateKey.generate()
        client_static_sk = X25519PrivateKey.generate()

        with tempfile.TemporaryDirectory() as tmpdir:
            client = x25519()
            client.keystore_path = os.path.join(tmpdir, "client.db")
            client_eph_pk, _, _ = client.initHE()

            client_h, client_enc_pk, _, _, _, client_ck = (
                client.agreeWithNoiseIKPatternMessage1(
                    client_static_private_key=client_static_sk,
                    client_enc_static_public_key=None,
                    server_static_public_key=server_static_sk.public_key(),
                    server_static_private_key=None,
                )
            )

            server_h, _, _, _, _, server_ck = x25519().agreeWithNoiseIKPatternMessage1(
                client_static_private_key=None,
                client_enc_static_public_key=client_enc_pk,
                server_static_public_key=None,
                server_static_private_key=server_static_sk,
                client_ephemeral_public_key=X25519PublicKey.from_public_bytes(
                    client_eph_pk
                ),
            )

            server_msg2 = x25519()
            server_msg2.keystore_path = os.path.join(tmpdir, "server.db")
            server_eph_pk, _, _ = server_msg2.initHE()

            server_h2, _, server_rk1, server_hk1, server_nhk1 = (
                server_msg2.agreeWithNoiseIKPatternMessage2(
                    client_ephemeral_public_key=X25519PublicKey.from_public_bytes(
                        client_eph_pk
                    ),
                    server_ephemeral_public_key=None,
                    server_static_public_key=None,
                    server_static_private_key=server_static_sk,
                    h=server_h,
                    ck=server_ck,
                )
            )

            client_h2, _, client_rk1, client_hk1, client_nhk1 = (
                client.agreeWithNoiseIKPatternMessage2(
                    client_ephemeral_public_key=None,
                    server_ephemeral_public_key=X25519PublicKey.from_public_bytes(
                        server_eph_pk
                    ),
                    server_static_public_key=server_static_sk.public_key(),
                    server_static_private_key=None,
                    h=client_h,
                    ck=client_ck,
                )
            )

            client_state = protocols.States()
            ratchetsHE.RatchetsHE.alice_init_HE(
                state=client_state,
                SK=client_rk1,
                bob_dh_public_key=server_eph_pk,
                shared_hka=client_hk1,
                shared_nhkb=client_nhk1,
                keystore_path=os.path.join(tmpdir, "client_ratchet.db"),
            )

            server_state = protocols.States()
            ratchetsHE.RatchetsHE.bob_init_HE(
                state=server_state,
                SK=server_rk1,
                bob_dh_key_pair=server_msg2,
                shared_hka=server_hk1,
                shared_nhkb=server_nhk1,
            )

            msg1 = b"Hello from client"
            enc_h1, ct1 = ratchetsHE.RatchetsHE.RatchetEncryptHE(
                state=client_state, plaintext=msg1, AD=client_h2
            )

            pt1 = ratchetsHE.RatchetsHE.RatchetDecryptHE(
                state=server_state, enc_header=enc_h1, ciphertext=ct1, AD=server_h2
            )

            assert pt1 == msg1

            msg2 = b"Reply from server"
            enc_h2, ct2 = ratchetsHE.RatchetsHE.RatchetEncryptHE(
                state=server_state, plaintext=msg2, AD=server_h2
            )

            pt2 = ratchetsHE.RatchetsHE.RatchetDecryptHE(
                state=client_state, enc_header=enc_h2, ciphertext=ct2, AD=client_h2
            )

            assert pt2 == msg2
