import os
import secrets
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
import time

# Define curves
curves = [ec.SECP192R1, ec.SECP224R1, ec.SECP256R1, ec.SECP384R1, ec.SECP521R1]

# Define message to sign
message_to_sign = b"This is a message to sign"

# Create empty dictionaries to store keys and timing
keypairs = {}
creation_time = {}
signing_time = {}

# Generate all keypairs first
for curve in curves:
    for i in range(11):
        # Create keypairs and record time
        start_time = time.time()
        private_key = ec.generate_private_key(
            curve()
        )
        public_key = private_key.public_key()
        end_time = time.time()

        # Save keys to file
        with open(f"ecdsa_{curve.name}_private_{i+1}.pem", "wb") as f:
            f.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
            )
        with open(f"ecdsa_{curve.name}_public_{i+1}.pem", "wb") as f:
            f.write(
                public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
            )

        creation_time[(curve.name, i)] = end_time - start_time
        keypairs[(curve.name, i)] = (public_key, private_key)

# Define verification_time dictionary
verification_time = {}  # Add this line
signatures = {}  # Add this line

# Then, digitally sign the hash
for curve in curves:
    for i in range(11):
        _, private_key = keypairs[(curve.name, i)]

        # Sign message and record time
        start_time = time.time()
        signature = private_key.sign(
            message_to_sign,
            ec.ECDSA(hashes.SHA256())
        )
        end_time = time.time()

        signing_time[(curve.name, i)] = end_time - start_time
        signatures[(curve.name, i)] = signature  # Store the signature

# Then, verify the signatures
for curve in curves:
    for i in range(11):
        public_key, _ = keypairs[(curve.name, i)]
        signature = signatures[(curve.name, i)]  # Retrieve the correct signature

        # Verify signature and record time
        start_time = time.time()
        try:
            public_key.verify(
                signature,
                message_to_sign,
                ec.ECDSA(hashes.SHA256())
            )
            end_time = time.time()
            verification_time[(curve.name, i)] = end_time - start_time
        except InvalidSignature:
            print(f"Signature verification for curve {curve.name}, index {i} failed.")

# Print timing
print("Creation time:", creation_time)
print("Signing time:", signing_time)
print("Verification time:", verification_time)
