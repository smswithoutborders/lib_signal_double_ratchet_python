import hashlib
from Crypto.Hash import SHA512, SHA256, HMAC
from Crypto.Protocol.KDF import HKDF


def build_verification_hash(auth_key, associated_data, cipher_text):
    if associated_data:
        input = associated_data + cipher_text
    else:
        input = cipher_text
    return HMAC.new(auth_key, digestmod=SHA256).update(input)


def get_mac_parameters(mk):
    hash_len = 80
    information = b"ENCRYPT"
    salt = bytes(hash_len)
    hkdf_out = HKDF(
        master=mk,
        key_len=hash_len,
        salt=salt,
        hashmod=SHA512,
        num_keys=1,
        context=information,
    )

    key = hkdf_out[:32]
    auth_key = hkdf_out[32:64]
    # iv = hkdf_out[64:]
    iv = hkdf_out[64 : (64 + 16)]

    return key, auth_key, iv


def verify_signature(mk, cipher_text_mac, associated_data):
    """
    Throws ValueError – if the MAC does not match.
    It means that the message has been tampered with or that
        the MAC key is incorrect.
    """
    _, auth_key, _ = get_mac_parameters(mk)
    mac = cipher_text_mac[len(cipher_text_mac) - SHA256.digest_size :]
    cipher_text = cipher_text_mac[: len(cipher_text_mac) - SHA256.digest_size]
    hmac = build_verification_hash(auth_key, associated_data, cipher_text)
    hmac.verify(mac)
    return cipher_text


def generate_associated_data_client(
    CI_sig_pk: bytes, SI_pk: bytes, message: str = "RelaySMS AD v1"
) -> bytes:
    """
    Client AD: HASH("RelaySMS AD v1" || CI_sig_pk || SI_pk)

    Args:
        CI_sig_pk: Client identity public key
        SI_pk: Server static public key
        message: Protocol message

    Returns:
        ad: SHA256 hash
    """
    h = hashlib.sha256()
    h.update(message.encode("utf-8"))
    h.update(CI_sig_pk)
    h.update(SI_pk)
    return h.digest()


def generate_associated_data_server(
    SI_pk: bytes, CI_sig_pk: bytes, message: str = "RelaySMS AD v1"
) -> bytes:
    """
    Server AD: HASH("RelaySMS AD v1" || SI_pk || CI_sig_pk)

    Args:
        SI_pk: Server static public key
        CI_sig_pk: Client identity public key
        message: Protocol message

    Returns:
        ad: SHA256 hash
    """
    h = hashlib.sha256()
    h.update(message.encode("utf-8"))
    h.update(SI_pk)
    h.update(CI_sig_pk)
    return h.digest()
