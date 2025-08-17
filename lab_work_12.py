# mini_pgp.py
# Implements two key PGP services for data in transit:
# - Authentication (digital signature)
# - Confidentiality (hybrid encryption: RSA + AES)
#
# Steps (Sign-then-Encrypt):
# 1) Sender hashes the plaintext and signs the hash with their RSA private key (AUTH).
# 2) Sender generates a random AES session key and encrypts (plaintext || signature) with AES-GCM (CONF + integrity).
# 3) Sender encrypts the AES session key with receiver's RSA public key (OAEP).
# 4) Receiver decrypts the AES key with RSA private key, then AES-decrypts the payload.
# 5) Receiver verifies the signature with sender's RSA public key.

import json, base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import pss
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

# ---------- Utility helpers ----------
def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("utf-8")

def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("utf-8"))

# ---------- Key generation (for demo) ----------
def generate_rsa_keypair(bits=2048):
    key = RSA.generate(bits)
    return key, key.publickey()

# ---------- AUTH: sign with sender's private key ----------
def sign_message(plaintext: bytes, sender_priv: RSA.RsaKey) -> bytes:
    h = SHA256.new(plaintext)
    signature = pss.new(sender_priv).sign(h)
    return signature

# ---------- CONF: hybrid encrypt (AES-GCM + RSA-OAEP) ----------
def encrypt_for_recipient(plaintext_and_sig: bytes, recipient_pub: RSA.RsaKey):
    # Generate random AES-256 session key
    session_key = get_random_bytes(32)  # 256-bit
    # Encrypt payload with AES-GCM
    nonce = get_random_bytes(12)  # recommended 96-bit nonce for GCM
    aes = AES.new(session_key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = aes.encrypt_and_digest(plaintext_and_sig)
    # Encrypt the session key with recipient's RSA public key
    rsa = PKCS1_OAEP.new(recipient_pub, hashAlgo=SHA256)
    enc_session_key = rsa.encrypt(session_key)
    # Package (this simulates the PGP message)
    package = {
        "enc_session_key": b64e(enc_session_key),
        "nonce": b64e(nonce),
        "tag": b64e(tag),
        "ciphertext": b64e(ciphertext),
    }
    return json.dumps(package).encode("utf-8")

# ---------- Receiver: decrypt & verify ----------
def decrypt_and_verify(pkg_bytes: bytes, recipient_priv: RSA.RsaKey, sender_pub: RSA.RsaKey):
    pkg = json.loads(pkg_bytes.decode("utf-8"))
    enc_session_key = b64d(pkg["enc_session_key"])
    nonce = b64d(pkg["nonce"])
    tag = b64d(pkg["tag"])
    ciphertext = b64d(pkg["ciphertext"])

    # Decrypt session key with recipient private key
    rsa = PKCS1_OAEP.new(recipient_priv, hashAlgo=SHA256)
    session_key = rsa.decrypt(enc_session_key)

    # Decrypt payload with AES-GCM
    aes = AES.new(session_key, AES.MODE_GCM, nonce=nonce)
    plaintext_and_sig = aes.decrypt_and_verify(ciphertext, tag)

    # Split plaintext || signature (we stored them as JSON before encryption)
    bundle = json.loads(plaintext_and_sig.decode("utf-8"))
    plaintext = b64d(bundle["plaintext"])
    signature = b64d(bundle["signature"])

    # Verify signature
    h = SHA256.new(plaintext)
    try:
        pss.new(sender_pub).verify(h, signature)
        verified = True
    except (ValueError, TypeError):
        verified = False

    return plaintext, verified

# ---------- Demo workflow ----------
if __name__ == "__main__":
    # 0) Keypairs
    alice_priv, alice_pub = generate_rsa_keypair()  # Sender (signs)
    bob_priv, bob_pub = generate_rsa_keypair()      # Receiver (decrypts)

    # 1) Sender prepares message
    message = b"PGP demo: Authentication + Confidentiality using RSA+AES."
    signature = sign_message(message, alice_priv)  # AUTH

    # 2) Sender creates a bundle (plaintext + signature) and encrypts it for Bob (CONF)
    bundle = {
        "plaintext": b64e(message),
        "signature": b64e(signature),
    }
    bundle_bytes = json.dumps(bundle).encode("utf-8")
    pgp_packet = encrypt_for_recipient(bundle_bytes, bob_pub)

    print("=== Transmitted PGP-like Packet (truncated) ===")
    print(json.dumps(json.loads(pgp_packet.decode()), indent=2)[:400] + "...\n")

    # 3) Receiver decrypts and verifies
    recovered_plaintext, ok = decrypt_and_verify(pgp_packet, bob_priv, alice_pub)

    print("=== Receiver Output ===")
    print("Decrypted message:", recovered_plaintext.decode("utf-8"))
    print("Signature verified:", "YES ✅" if ok else "NO ❌")
