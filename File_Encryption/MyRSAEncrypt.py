import json, requests, os, socket, sys, base64, cryptography
import binascii

from CONSTANTS import *
from MyfileEncryptMAC import *

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, serialization, hashes, hmac, asymmetric
from cryptography.hazmat.primitives.asymmetric import rsa

def MyRSAEncrypt(filepath, RSA_PublicKey_filepath):
    # Encrypt file
    MyfileEncryptMAC(filepath)
    file = open('..\\..\\data.json', 'r')
    data = json.load(file)
    file.close()

    # Convert data to bytes
    C = binascii.unhexlify(data['C'].encode('utf-8'))
    IV = binascii.unhexlify(data['IV'].encode('utf-8'))
    tag = binascii.unhexlify(data['tag'].encode('utf-8'))
    EncKey = binascii.unhexlify(data['EncKey'].encode('utf-8'))
    HMACKey = binascii.unhexlify(data['HMACKey'].encode('utf-8'))

    # Get ext
    ext = data['ext']
    
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
    
    # Create tag
    digest = hmac.HMAC(HMACKey, hashes.SHA256(), backend = default_backend())
    digest.update(C)
    tag = digest.finalize()
    
    # Convert data to strings
    RSACipherString = binascii.hexlify(RSACipher).decode('utf-8')
    CString = binascii.hexlify(C).decode('utf-8')
    IVString = binascii.hexlify(IV).decode('utf-8')
    tagString = binascii.hexlify(tag).decode('utf-8')
    
    # Store in JSON
    RSAdata = {'RSACipher': RSACipherString, 'C': CString, 'IV': IVString,
            'tag': tagString, 'ext': ext}
    
    file = open('..\\..\\RSAdata.json', 'w')
    json.dump(RSAdata, file)
    file.close()

    return RSACipher, C, IV, tag, ext
    
def MyRSADecrypt(RSA_PrivateKey_filepath):
    # Read RSA data from JSON
    file = open('..\\..\\RSAdata.json', 'r')
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
    
    # Verify Tag
    verificationTag = hmac.HMAC(HMACKey, hashes.SHA256(),
                                backend = default_backend())
    verificationTag.update(C)
    verificationTag.verify(tag)
    
    
    # Decrypt
    message = MydecryptMAC(C, IV, tag, EncKey, HMACKey)

    # Output
    if(ext == '.txt'):
        message = message.decode()
        file = open('..\\..\\decodedFile.txt', 'w')
        file.write(message)
        file.close()
    else:
        file = open('..\\..\\decodedFile' + ext, 'wb')
        file.write(message)
        file.close()
            
    return message

if __name__ == "__main__":
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
    
    file = open('..\\..\\rsa_public_key.pem', 'wb')
    file.write(publicKey)
    file.close()
    
    # Create and write private key
    privateKey = key.private_bytes(
        encoding = serialization.Encoding.PEM,
        format = serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm = serialization.NoEncryption()
        )
    
    f = open('..\\..\\rsa_private_key.pem', 'wb')
    f.write(privateKey)
    f.close()
    
    # Calling RSA Encryptor Decryptor modules
    mypath = "..\\Test_Files\\JPEG_test.jpeg"
    RSA_PublicKey_filepath = '..\\..\\rsa_public_key.pem'
    RSA_PrivateKey_filepath = '..\\..\\rsa_private_key.pem'
    
    MyRSAEncrypt(mypath, RSA_PublicKey_filepath)
    MyRSADecrypt(RSA_PrivateKey_filepath)