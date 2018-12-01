# Eleazar Gomez
# Dion Woo
#
# RSA File Step 1: checkKeys

from os import scandir

from CONSTANTS import *

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

# void = checkKeys()
#
# Next, you will a script that looks for a pair of RSA Public
# and private key (using a CONSTANT file path; PEM format).

def checkKeys():
    publicKeyChecker = False
    privateKeyChecker = False

    # Search directory for pair of keys
    with scandir(RSA_KEYS_DIRECTORY) as it:
        for entry in it:
            if not entry.name.startswith('.') and entry.is_file():
                if(entry.name == RSA_PUBLIC_KEY_FILENAME):
                    publicKeyChecker = True
                if(entry.name == RSA_PRIVATE_KEY_FILENAME):
                    privateKeyChecker = True

    # If either key is not found, generate new keys       
    if(publicKeyChecker == False or privateKeyChecker == False):
        print("There are no existing key(s)! Keys will now be generated.")
        generateKeys()

# void = generateKeys()
#
# If the files do not exist then generate the RSA
# public and private key (2048 bits length) using the same constant
# file path.

def generateKeys():
    # Generate RSA key for key pairs
    key = rsa.generate_private_key(
        public_exponent = RSA_PUBLIC_EXPONENT,
        key_size = RSA_KEY_SIZE,
        backend = default_backend()
        )
    
    # Create and write public key
    public = key.public_key()
    publicKey = public.public_bytes(
        encoding = serialization.Encoding.PEM,
        format = serialization.PublicFormat.SubjectPublicKeyInfo
        )
    
    file = open(RSA_PUBLIC_KEY_FILEPATH, 'wb')
    file.write(publicKey)
    file.close()
    
    # Create and write private key
    privateKey = key.private_bytes(
        encoding = serialization.Encoding.PEM,
        format = serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm = serialization.NoEncryption()
        )
    
    f = open(RSA_PRIVATE_KEY_FILEPATH, 'wb')
    f.write(privateKey)
    f.close()

# =====================
# TEST
# =====================

if __name__ == "__main__":
    checkKeys()

