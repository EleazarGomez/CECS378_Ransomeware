# Eleazar Gomez
# Dion Woo
#
# RSA File Step 3: Decrypt

from os import remove

from MyRSAEncrypt import *
from CONSTANTS import *

# void = Decrypt(fileInfo)
#
# Using the result of the Encrypt method, decrypt all the files and remove
# the JSONs.

def Decrypt(fileInfo):
    for item in fileInfo:
        # Decrypt
        MyRSADecrypt(item[0], item[1], RSA_PRIVATE_KEY_FILEPATH)

        # Remove JSON
        remove(item[0] + "\\" + item[1] + ".json")
