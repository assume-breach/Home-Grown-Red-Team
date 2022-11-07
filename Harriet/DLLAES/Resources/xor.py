# Red Team Operator course code template
# payload encryption with XOR
#
# author: reenz0h (twitter: @sektor7net)

import sys

KEY = "YnNMojLDpktrJDj"

def xor(data, key):
	l = len(key)
	output_str = ""

	for i in range(len(data)):
		current = data[i]
		current_key = key[i%len(key)]
		output_str += chr(ord(current) ^ ord(current_key))
	
	return output_str

def printC(ciphertext):
	print('{ 0x' + ', 0x'.join(hex(ord(x))[2:] for x in ciphertext) + ' };')

try:
    plaintext = open(sys.argv[1], "r").read()
except:
    print("File argument needed! %s <raw payload file>" % sys.argv[0])
    sys.exit()

ciphertext = xor(plaintext, KEY)

printC(ciphertext)
