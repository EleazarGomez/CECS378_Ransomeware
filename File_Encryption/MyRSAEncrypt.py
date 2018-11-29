import json, os, cryptography
import binascii

from CONSTANTS import *
from MyfileEncryptMAC import *

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, serialization, hashes, hmac, asymmetric
from cryptography.hazmat.primitives.asymmetric import rsa

def MyRSAEncrypt(filepath, RSA_PublicKey_filepath):
    # Encrypt file
    filename, C, IV, tag, EncKey, HMACKey, ext = MyfileEncryptMAC(filepath)
    
    # Concatenate encryption key and hmac key
    keysConcatenated = EncKey + HMACKey
    
    # Read public key
    file = open(RSA_PublicKey_filepath, 'rb')
    publicKey = serialization.load_pem_public_key(file.read(),
                                                  default_backend())
    file.close()

    # Create cipher for public key
    RSACipher = publicKey.encrypt(keysConcatenated,
                                   asymmetric.padding.OAEP(
                                       mgf = asymmetric.padding.MGF1(
                                           algorithm = hashes.SHA256()),
                                       algorithm = hashes.SHA256(),
                                       label = None)
                                   )
    
    # Convert data to strings
    RSACipherString = binascii.hexlify(RSACipher).decode('utf-8')
    CString = binascii.hexlify(C).decode('utf-8')
    IVString = binascii.hexlify(IV).decode('utf-8')
    tagString = binascii.hexlify(tag).decode('utf-8')
    
    # Store in JSON
    RSAdata = {'RSACipher': RSACipherString, 'C': CString, 'IV': IVString,
            'tag': tagString, 'ext': ext}
    
    file = open('..\\..\\' + filename + 'ENC.json', 'w')
    json.dump(RSAdata, file)
    file.close()

    return filename
    
def MyRSADecrypt(filename, RSA_PrivateKey_filepath):
    # Read RSA data from JSON
    file = open('..\\..\\' + filename + 'ENC.json', 'r')
    RSAdata = json.load(file)
    file.close()

    # Read private key
    file = open(RSA_PrivateKey_filepath, 'rb')
    privateKey = serialization.load_pem_private_key(file.read(),
                                                    password = None,
                                                    backend = default_backend()
                                                    )

    # Convert data to bytes
    RSACipher = binascii.unhexlify(RSAdata['RSACipher'].encode('utf-8'))
    C = binascii.unhexlify(RSAdata['C'].encode('utf-8'))
    IV = binascii.unhexlify(RSAdata['IV'].encode('utf-8'))
    tag = binascii.unhexlify(RSAdata['tag'].encode('utf-8'))

    # Get ext
    ext = RSAdata['ext']
    
    # Decrypt private key
    key = privateKey.decrypt(RSACipher,
                             asymmetric.padding.OAEP(
                                 mgf = asymmetric.padding.MGF1(
                                     algorithm = hashes.SHA256()),
                                 algorithm = hashes.SHA256(),
                                 label=None)
                             )
    
    # Retrieve encryption and hmac keys
    EncKey = key[0:32]
    HMACKey = key[32:64]
    
    # Decrypt
    message = MyfileDecryptMAC(filename, C, IV, tag, EncKey, HMACKey, ext)


def generateKeys():
    # Generate RSA key for key pairs
    key = rsa.generate_private_key(
        public_exponent = 65537,
        key_size = 2048,
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

def checkKeys():
    publicKeyChecker = False
    privateKeyChecker = False

    # Search directory for pair of keys
    with os.scandir(RSA_KEYS_DIRECTORY) as it:
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
    

if __name__ == "__main__":
    checkKeys()
    
    # Calling RSA Encryptor Decryptor modules
    testFilePath = "..\\Test_Files\\JPEG_test.jpeg"
    
    x = MyRSAEncrypt(testFilePath, RSA_PUBLIC_KEY_FILEPATH)
    MyRSADecrypt(x, RSA_PRIVATE_KEY_FILEPATH)
