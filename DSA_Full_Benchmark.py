import os
import secrets
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
import time

# Define key sizes
key_sizes = [1024, 2048, 3072]

# Define message to sign
message_to_sign = b"This is a message to sign"

# Create empty dictionaries to store keys and timing
keypairs = {}
creation_time = {}
signing_time = {}

# Generate all keypairs first
for key_size in key_sizes:
    for i in range(11):
        # Create keypairs and record time
        start_time = time.time()
        private_key = dsa.generate_private_key(
            key_size=key_size
        )
        public_key = private_key.public_key()
        end_time = time.time()

        # Save keys to file
        with open(f"dsa_{key_size}_private_{i+1}.pem", "wb") as f:
            f.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
            )
        with open(f"dsa_{key_size}_public_{i+1}.pem", "wb") as f:
            f.write(
                public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
            )

        creation_time[(key_size, i)] = end_time - start_time
        keypairs[(key_size, i)] = (public_key, private_key)

# Define verification_time dictionary
verification_time = {}  # Add this line
signatures = {}  # Add this line

# Then, digitally sign the hash
for key_size in key_sizes:
    for i in range(11):
        _, private_key = keypairs[(key_size, i)]

        # Sign message and record time
        start_time = time.time()
        signature = private_key.sign(
            message_to_sign,
            hashes.SHA256()
        )
        end_time = time.time()

        signing_time[(key_size, i)] = end_time - start_time
        signatures[(key_size, i)] = signature  # Store the signature

# Then, verify the signatures
for key_size in key_sizes:
    for i in range(11):
        public_key, _ = keypairs[(key_size, i)]
        signature = signatures[(key_size, i)]  # Retrieve the correct signature

        # Verify signature and record time
        start_time = time.time()
        try:
            public_key.verify(
                signature,
                message_to_sign,
                hashes.SHA256()
            )
            end_time = time.time()
            verification_time[(key_size, i)] = end_time - start_time
        except InvalidSignature:
            print(f"Signature verification for key size {key_size}, index {i} failed.")

# Print timing
print("Creation time:", creation_time)
print("Signing time:", signing_time)
print("Verification time:", verification_time)
