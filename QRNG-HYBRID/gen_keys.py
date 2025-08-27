
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

priv_pem = key.private_bytes(
    serialization.Encoding.PEM,
    serialization.PrivateFormat.PKCS8,
    serialization.NoEncryption(),  # demo only; use a password in real life
)
pub_pem = key.public_key().public_bytes(
    serialization.Encoding.PEM,
    serialization.PublicFormat.SubjectPublicKeyInfo,
)

open("receiver_private.pem", "wb").write(priv_pem)
open("receiver_public.pem", "wb").write(pub_pem)
print("Wrote receiver_private.pem and receiver_public.pem")
