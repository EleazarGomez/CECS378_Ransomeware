# Eleazar Gomez
# Dion Woo
#
# RSA File Step 2: MyRSAEncrypt and MyRSADecrypt

from os import remove
import json
import binascii

from CONSTANTS import *
from MyfileEncryptMAC import *
from checkKeys import *

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes, asymmetric

# (pathToFile, filename) = MyRSAEncrypt(filepath, RSA_Publickey_filepath)
#
# In this method, you first call MyfileEncryptMAC (filepath) which will
# return (C, IV, tag, Enckey, HMACKey, ext). You then will initialize an
# RSA public key encryption object and load pem publickey from the
# RSA_publickey_filepath. Lastly, you encrypt the key variable
# ("key" = EncKey + HMACKey (concatenated)) using the RSA publickey in OAEP
# padding mode. The result will be RSACipher. You then return
# (RSACipher, C, IV, ext).


def MyRSAEncrypt(filepath, RSA_PublicKey_filepath):
    # Encrypt file
    pathToFile, filename, C, IV, tag, EncKey, HMACKey, ext = MyfileEncryptMAC(filepath)
    
    # Concatenate encryption key and hmac key
    keysConcatenated = EncKey + HMACKey
    
    # Read public key
    file = open(RSA_PublicKey_filepath, 'rb')
    publicKey = serialization.load_pem_public_key(file.read(),
                                                  default_backend())
    file.close()

    # Create cipher for public key (OAEP padding, SHA256)
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
    
    # Store data in JSON (RSACipher, C, IV, tag, ext)
    RSAdata = {'RSACipher': RSACipherString, 'C': CString, 'IV': IVString,
            'tag': tagString, 'ext': ext}
    
    file = open(pathToFile + "\\" + filename + '.json', 'w')
    json.dump(RSAdata, file)
    file.close()

    # Return the data (pathToFile, filename)
    return pathToFile, filename

# message = MyRSADecrypt(pathToFile, filename, RSA_PrivateKey_filepath)
#
# Inverse of MyRSAEncrypt. Returns the decrypted message.

def MyRSADecrypt(pathToFile, filename, RSA_PrivateKey_filepath):
    # Read RSA data from JSON
    file = open(pathToFile + "\\" + filename + '.json', 'r')
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
    message = MyfileDecryptMAC(pathToFile, filename, C, IV, tag, EncKey, HMACKey, ext)

    # Return the message
    return message

# =====================
# TEST
# =====================

if __name__ == "__main__":
    checkKeys()
    
    # Calling RSA Encryptor Decryptor modules
    testFilePath = ".\\JPEG_test.jpeg"
    
    x, y = MyRSAEncrypt(testFilePath, RSA_PUBLIC_KEY_FILEPATH)
    remove(x + "\\" + y + '.jpeg')
    MyRSADecrypt(x, y, RSA_PRIVATE_KEY_FILEPATH)
