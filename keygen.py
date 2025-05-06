from Crypto.PublicKey import RSA
import os

KEY_SIZE = 2048
CLIENT_PRIVATE_KEY_FILE = "SiFTv0.5 3/client/private_key.pem"
CLIENT_PUBLIC_KEY_FILE = "SiFTv0.5 3/client/public_key.pem"
SERVER_PUBLIC_KEY_FILE = "SiFTv0.5 3/server/public_key.pem"
PRIVATE_KEY_PASSPHRASE = "rsa_key"  # You can choose a stronger one


#  Generate RSA Key Pair
keypair = RSA.generate(KEY_SIZE)

#  Export and save Private Key (encrypted) 
private_key = keypair.export_key(
    format='PEM',
    passphrase=PRIVATE_KEY_PASSPHRASE,
)

with open(CLIENT_PRIVATE_KEY_FILE, 'wb') as f:
    f.write(private_key)
print(f"🔐 Private key saved to {CLIENT_PRIVATE_KEY_FILE}")

#  Export and save Public Key 
public_key = keypair.publickey().export_key(format='PEM')
with open(SERVER_PUBLIC_KEY_FILE, 'wb') as f:
    f.write(public_key)
print(f"🔓 Public key saved to {SERVER_PUBLIC_KEY_FILE}")

with open(CLIENT_PUBLIC_KEY_FILE, 'wb') as f:
    f.write(public_key)
print(f"🔓 Public key saved to {CLIENT_PUBLIC_KEY_FILE}")
