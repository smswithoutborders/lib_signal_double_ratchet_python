"""Test utilities."""

from cryptography.hazmat.primitives import constant_time

from smswithoutborders_libsig.keypairs import Keypairs
from smswithoutborders_libsig.protocols import HEADERS, States


def states_equal(state1, state2) -> bool:
    """Compare two States objects."""

    if not isinstance(state1, States) or not isinstance(state2, States):
        return False

    dhr_equal = constant_time.bytes_eq(
        state1.DHr if state1.DHr else b"", state2.DHr if state2.DHr else b""
    )
    rk_equal = constant_time.bytes_eq(
        state1.RK if state1.RK else b"", state2.RK if state2.RK else b""
    )
    cks_equal = constant_time.bytes_eq(
        state1.CKs if state1.CKs else b"", state2.CKs if state2.CKs else b""
    )
    ckr_equal = constant_time.bytes_eq(
        state1.CKr if state1.CKr else b"", state2.CKr if state2.CKr else b""
    )

    return (
        keypairs_equal(state1.DHs, state2.DHs)
        and dhr_equal
        and rk_equal
        and cks_equal
        and ckr_equal
        and state1.Ns == state2.Ns
        and state1.Nr == state2.Nr
        and state1.PN == state2.PN
        and state1.MKSKIPPED == state2.MKSKIPPED
    )


def headers_equal(header1, header2) -> bool:
    """Compare two HEADERS objects."""

    if not isinstance(header1, HEADERS) or not isinstance(header2, HEADERS):
        return False

    return (
        constant_time.bytes_eq(header1.dh, header2.dh)
        and header1.pn == header2.pn
        and header1.n == header2.n
    )


def keypairs_equal(keypair1, keypair2) -> bool:
    """Compare two Keypairs objects."""

    if not isinstance(keypair1, Keypairs) or not isinstance(keypair2, Keypairs):
        return False

    return (
        keypair1.keystore_path == keypair2.keystore_path
        and keypair1.pnt_keystore == keypair2.pnt_keystore
        and constant_time.bytes_eq(
            keypair1.secret_key.encode(), keypair2.secret_key.encode()
        )
    )
