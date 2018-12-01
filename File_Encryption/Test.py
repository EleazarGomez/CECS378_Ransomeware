# Eleazar Gomez
# Dion Woo
#
# RSA File Step 3: Executable

from Encrypt import *
from Decrypt import *     
    

# ================================
# TEST
# do not run on important folders
# ================================

if __name__ == "__main__":
    print("Press Enter to Encrypt: ")
    input()
    fileInfo = Encrypt()
    print("Press Enter to Decrypt: ")
    input()
    Decrypt(fileInfo)
