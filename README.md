# Hybrid-Encryption--QRNG
# 1) Keys (once)
python gen_keys.py

# 2) Test file
echo "Hello Quantum Hackathon!" > demo.txt

# 3) Sender side
python encrypt.py --infile demo.txt --pub receiver_public.pem --out bundle.json --aad "filename:demo.txt"

# 4) Receiver side
python decrypt.py --bundle bundle.json --priv receiver_private.pem --out demo.out.txt

# 5) Verify
diff demo.txt demo.out.txt && echo "Match ✅"
