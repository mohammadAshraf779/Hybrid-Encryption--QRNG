import streamlit as st, json, base64, pathlib
from encrypt import encrypt_for_recipient
from decrypt import decrypt_bundle

st.title("QRNG Hybrid Encryption Demo")

tab1, tab2 = st.tabs(["Encrypt (Sender)", "Decrypt (Receiver)"])

with tab1:
    pub_pem = st.file_uploader("Receiver public key (PEM)", type=["pem"])
    up = st.file_uploader("File to encrypt")
    aad = st.text_input("AAD (optional)", "filename:uploaded.bin")
    if st.button("Encrypt with QRNG") and pub_pem and up:
        bundle = encrypt_for_recipient(up.read(), pub_pem.name, aad.encode() if aad else None)
        st.success("Encrypted!")
        st.download_button("Download bundle.json", data=json.dumps(bundle), file_name="bundle.json")

with tab2:
    priv_pem = st.file_uploader("Receiver private key (PEM)", type=["pem"])
    bundle_file = st.file_uploader("bundle.json", type=["json"])
    if st.button("Decrypt") and priv_pem and bundle_file:
        bundle = json.loads(bundle_file.read().decode())
        out = decrypt_bundle(bundle, priv_pem.name)
        st.success("Decrypted!")
        st.download_button("Download plaintext", data=out, file_name="decrypted.bin")
