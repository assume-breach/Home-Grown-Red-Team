# Red Team Operator course code template
# payload encryption with AES
# 
# author: reenz0h (twitter: @SEKTOR7net)

import sys
from base64 import b64encode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
import hashlib

KEY = get_random_bytes(16)
iv = 16 * b'\x00'
cipher = AES.new(hashlib.sha256(KEY).digest(), AES.MODE_CBC, iv)

try:
    plaintext = open(sys.argv[1], "rb").read()
except:
    print("File argument needed! %s <raw payload file>" % sys.argv[0])
    sys.exit()

ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))

print('AESkey[] = { 0x' + ', 0x'.join(hex(x)[2:] for x in KEY) + ' };')
print('payload[] = { 0x' + ', 0x'.join(hex(x)[2:] for x in ciphertext) + ' };')
