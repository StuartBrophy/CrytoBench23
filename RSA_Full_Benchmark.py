import os
import secrets
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
import time

# Define key sizes
key_sizes = [1024, 2048, 3072, 7680, 15360]

# Define message to sign
message_to_sign = b"This is a message to sign"

# Create empty dictionaries to store keys and timing
keypairs = {}
creation_time = {}
encryption_time = {}
decryption_time = {}
signing_time = {}
verification_time = {}
signatures = {}

# Generate Keypairs
for key_size in key_sizes:
    for i in range(11):
        # Create Keypairs
        start_time = time.time()
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size
        )
        public_key = private_key.public_key()
        end_time = time.time()

        # Save Keys file
        with open(f"rsa_{key_size}_private_{i+1}.pem", "wb") as f:
            f.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
            )
        with open(f"rsa_{key_size}_public_{i+1}.pem", "wb") as f:
            f.write(
                public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
            )

        creation_time[(key_size, i)] = end_time - start_time
        keypairs[(key_size, i)] = (public_key, private_key)

# Encryption
for key_size in key_sizes:
    for i in range(11):
        public_key, _ = keypairs[(key_size, i)]
        max_size = key_size // 8 - 2*32 - 2
        plaintext = os.urandom(max_size)
        print(f"Plaintext length: {len(plaintext)}") 

        # Encrypt Plaintext
        start_time = time.time()
        ciphertext = public_key.encrypt(
            plaintext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        end_time = time.time()

        # Save Ciphertext file
        with open(f"ciphertext_{key_size}_{i+1}.bin", "wb") as f:
            f.write(ciphertext)

        encryption_time[(key_size, i)] = end_time - start_time

# Decryption
for key_size in key_sizes:
    for i in range(11):
        _, private_key = keypairs[(key_size, i)]
        
        # Load Ciphertext from file
        with open(f"ciphertext_{key_size}_{i+1}.bin", "rb") as f:
            ciphertext = f.read()

        # Decrypt Ciphertext
        start_time = time.time()
        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        end_time = time.time()

        decryption_time[(key_size, i)] = end_time - start_time

# Digitally Sign Hash
for key_size in key_sizes:
    for i in range(11):
        _, private_key = keypairs[(key_size, i)]

        # Sign Message
        start_time = time.time()
        signature = private_key.sign(
            message_to_sign,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        end_time = time.time()
        signing_time[(key_size, i)] = end_time - start_time
        signatures[(key_size, i)] = signature  # Store the signature

# Verify the Signatures
for key_size in key_sizes:
    for i in range(11):
        public_key, _ = keypairs[(key_size, i)]
        signature = signatures[(key_size, i)]  # Retrieve the correct signature

        # Verify Signature
        start_time = time.time()
        try:
            public_key.verify(
                signature,
                message_to_sign,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            end_time = time.time()
            verification_time[(key_size, i)] = end_time - start_time
        except InvalidSignature:
            print(f"Signature verification for key size {key_size}, index {i} failed.")

# Print Results
print("Creation time:", creation_time)
print("Encryption time:", encryption_time)
print("Decryption time:", decryption_time)
print("Signing time:", signing_time)
print("Verification time:", verification_time)