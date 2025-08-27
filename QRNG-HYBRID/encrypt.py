
import argparse, base64, json, pathlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from qrng import qrng_bytes

def load_public_key(pem_path: str):
    data = pathlib.Path(pem_path).read_bytes()
    return serialization.load_pem_public_key(data)

def encrypt_for_recipient(plaintext: bytes, pubkey_pem_path: str, aad: bytes|None=None) -> dict:
    # 1) QRNG-driven AES key & nonce
    aes_key = qrng_bytes(32)     # 256-bit
    nonce  = qrng_bytes(12)      # 96-bit (standard for GCM)
    aes = AESGCM(aes_key)

    # 2) AES-GCM encryption (ciphertext || tag)
    ciphertext = aes.encrypt(nonce, plaintext, aad)

    # 3) Wrap the AES key using RSA-OAEP(SHA-256)
    pubkey = load_public_key(pubkey_pem_path)
    enc_key = pubkey.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # 4) Package bundle
    return {
        "alg": "AES-256-GCM + RSA-OAEP-SHA256",
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),  # includes tag at the end
        "enc_key": base64.b64encode(enc_key).decode(),
        "aad": base64.b64encode(aad).decode() if aad else None,
        "meta": {"note": "prototype", "ver": 1}
    }

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--infile", required=True)
    ap.add_argument("--pub", required=True, help="receiver_public.pem")
    ap.add_argument("--out", required=True, help="bundle.json")
    ap.add_argument("--aad", help="optional associated data string")
    args = ap.parse_args()

    data = pathlib.Path(args.infile).read_bytes()
    aad = args.aad.encode() if args.aad else None
    bundle = encrypt_for_recipient(data, args.pub, aad)
    pathlib.Path(args.out).write_text(json.dumps(bundle))
    print(f"Wrote {args.out}")

if __name__ == "__main__":
    main()
