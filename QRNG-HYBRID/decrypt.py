
import argparse, base64, json, pathlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

def load_private_key(pem_path: str, password: bytes|None=None):
    data = pathlib.Path(pem_path).read_bytes()
    return serialization.load_pem_private_key(data, password=password)

def decrypt_bundle(bundle: dict, priv_pem_path: str, password: bytes|None=None) -> bytes:
    priv = load_private_key(priv_pem_path, password=password)

    enc_key = base64.b64decode(bundle["enc_key"])
    nonce = base64.b64decode(bundle["nonce"])
    ciphertext = base64.b64decode(bundle["ciphertext"])
    aad = base64.b64decode(bundle["aad"]) if bundle.get("aad") else None

    # 1) Unwrap AES key with RSA-OAEP
    aes_key = priv.decrypt(
        enc_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # 2) Decrypt with AES-GCM
    aes = AESGCM(aes_key)
    return aes.decrypt(nonce, ciphertext, aad)

def main():
    # ap = argparse.ArgumentParser()
    # ap.add_argument("--bundle", required=True, help="bundle.json")
    # ap.add_argument("--priv", required=True, help="receiver_private.pem")
    # ap.add_argument("--out", required=True, help="decrypted output file")
    # args = ap.parse_args()

    # bundle = json.loads(pathlib.Path(args.bundle).read_text())
    # plaintext = decrypt_bundle(bundle, args.priv)
    # pathlib.Path(args.out).write_bytes(plaintext)
    # print(f"Wrote {args.out}")

    ap = argparse.ArgumentParser()
    ap.add_argument("--bundle", required=True, help="bundle.json")
    ap.add_argument("--priv", required=True, help="receiver_private.pem")
    ap.add_argument("--out", required=True, help="decrypted output file")
    args = ap.parse_args()

    print(f"[+] Loading bundle from {args.bundle}")
    bundle = json.loads(pathlib.Path(args.bundle).read_text())

    print(f"[+] Decrypting with private key {args.priv}")
    try:
        plaintext = decrypt_bundle(bundle, args.priv)
        pathlib.Path(args.out).write_bytes(plaintext)
        print(f"[+] Wrote decrypted file to {args.out}")
    except Exception as e:
        print(f"[!] Decryption failed: {e}")


if __name__ == "__main__":
    main()
