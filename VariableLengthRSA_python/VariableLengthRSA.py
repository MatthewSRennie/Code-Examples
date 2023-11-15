# Created by Matt Rennie
# Variable Length RSA
# VariableLengthRSA.py
# 
# This program can be used to encrypt a variable length RSA message (as opposed to the typical fixed length)
# To use, simply run the program
# You can either specify your own keys, or generate keys using the program
#
# This program has the same function as VariableLengthRSA.java, but is written in Python rather than Java

import random
import math
import sys
import os.path

NUM_BITS = 2048
BLOCK_SIZE = 214 
PRIME_ITER = 100

def gcd (a, b):
	while (b != 0):
		r = a % b
		a = b
		b = r
	return a;

def powMod(b, e, m):
	z = 1
	while (e > 0):
		if ((e % 2) == 1):
			z = (z * b) % m
		e = e >> 1
		b = (b * b) % m;
	return z

def calcInverseMod(num, mod):
	num = num % mod
	t = 0
	newt = 1
	r = mod
	newr = num

	while (newr != 0):
		quo = r // newr
		temp = newr
		newr = r - (quo * newr)
		r = temp
		temp = newt
		newt = t - (quo * newt)
		t = temp

	if (r > 1):
		print("Error finding inverse")
		return -1
		
	if (t < 0):
		t = t + mod

	return t
	
def findPrime(length):
	i = 1
	num = random.getrandbits(length)
	while (ssPrimeTest(num, PRIME_ITER) == False):
		i = i + 1
		num = random.getrandbits(length)
	
	print("Prime generated after " + str(i) + " attempts")
	print("Tested with Solovay-Strassen " + str(PRIME_ITER) + " times.")
	print("Chance it is not prime is: " + str(ssAcc(num)))
	return num

def jacobi(a, n):
	if (gcd(a,n) != 1):
		return -2;
	
	return jacobiHelper(a, n, 1)

def jacobiHelper(a, n, negative):
	a = a % n

	if (a == 0):
		return negative

	while (a % 2 == 0):
		if (a == 0):
			return -2
		
		a = a // 2
		if (n % 8 == 3 or n % 8 == 5):
			negative *= -1

	if (a % 4 == 3 and n % 4 == 3):
		negative *= -1

	return jacobiHelper(n, a, negative)

def findE(phiN):
	e = random.getrandbits(NUM_BITS)
	e = e % phiN
	while(gcd(e, phiN) != 1):
		e = random.getrandbits(NUM_BITS)
		e = e % phiN

	return e

def ssPrimeTest(p, iterations):
	if (p < 2):
		return False

	if (p != 2 and (p % 2) == 0):
		return False

	for i in range(0, iterations):
		randomA = random.getrandbits(NUM_BITS)
		randomA = (randomA % (p - 1)) + 1
		jacobian = (p + jacobi(randomA, p)) % p
		mod = powMod(randomA, (p - 1) // 2, p)
		if (jacobian == 0 or mod != jacobian):
			return False
	return True

def ssAcc(n):
	logN = math.log(n)
	logN = (logN - 2.0) / (logN - 2.0 + math.pow(2, PRIME_ITER - 1))
	return logN
	
def calcPhi(a,b):
	return (a-1)*(b-1)
	
def createKeys():
	p = findPrime(NUM_BITS//2)
	q = findPrime(NUM_BITS//2)
	phi = calcPhi(p, q)
	n = (p * q)
	e = findE(phi)
	d = calcInverseMod(e, phi)
	print("n = " + str(n))
	print("e = " + str(e))
	print("d = " + str(d))
	return {'n':n,'e':e,'d':d}

def encrypt(e, n, data):
	if isinstance(data, str):
		strBytes = data.encode(encoding="utf-8",errors="strict")
		data = int.from_bytes(strBytes, byteorder="big", signed=False)
	return encryptHelper(e,n,data)

def encryptHelper(e, n, data):
	data = data + 0 # make sure it is a number
	data = padInt(data, BLOCK_SIZE)
	numBytes = (data.bit_length() + 7) // 8
	databytes = data.to_bytes(numBytes,byteorder="big",signed=False)
	if (numBytes % BLOCK_SIZE != 0):
		print("Error: padding incorrect")
	numBlocks = numBytes // BLOCK_SIZE
	
	resultArray = bytearray()
	for i in range(0,numBlocks):
		current = databytes[i*BLOCK_SIZE:(i+1)*BLOCK_SIZE]
		currentInt = int.from_bytes(current,byteorder="big",signed=False)
		currentInt = powMod(currentInt, e, n)
		resultArray = resultArray + currentInt.to_bytes(NUM_BITS//8,byteorder="big",signed=False)
		
	return int.from_bytes(resultArray, byteorder="big", signed=False)

def decrypt(d, n, data):
	data = int(data)
	data = data + 0 # make sure it is a number
	numBytes = (data.bit_length() + 7) // 8
	numBlocks = math.ceil(numBytes / (NUM_BITS/8))
	databytes = bytearray()
	databytes = databytes + data.to_bytes(numBlocks * (NUM_BITS//8),byteorder="big",signed=False)
	
	resultArray = bytearray()
	for i in range(0,numBlocks):
		current = databytes[i*(NUM_BITS//8):(i+1)*(NUM_BITS//8)]
		currentInt = int.from_bytes(current,byteorder="big",signed=False)
		currentInt = powMod(currentInt, d, n)
		resultArray = resultArray + currentInt.to_bytes(BLOCK_SIZE,byteorder="big",signed=False)
	return int.from_bytes(removePadding(resultArray),byteorder="big",signed=False)
	

def padInt(num, block_size):
	numBytes = (num.bit_length() + 7) // 8
	theBytes = num.to_bytes(numBytes,byteorder="big",signed=False)
	toPad = (block_size - (numBytes % block_size)) % block_size;
	for i in range(0,toPad): # add padding
		theBytes = theBytes + bytes([0])
	res = int.from_bytes(theBytes, byteorder="big", signed=False)
	return res

def intToStr(num):
	numStr = num.to_bytes((num.bit_length() + 7) // 8, byteorder="big", signed=False)
	return numStr.decode("utf-8")

def removePadding(arr):
	numBytes = len(arr)
	i = numBytes - 1
	num = int.from_bytes(arr[i:i],byteorder="big",signed=False)
	
	while (i >= 0 and num == 0):
		i = i - 1
		num = int.from_bytes(arr[i:i+1],byteorder="big",signed=False)
	return arr[0:i+1]

def writeFile(fileName, data):
	f = open(fileName, 'w')
	f.write(data)

def readFile(fileName):
	f = open(fileName, 'r')
	return f.read()

def checkFile(fileName):
	return path.exists(fileName)

def testMain():
	keys = createKeys()
	encryptedMessage = encrypt(keys['e'],keys['n'],"abcd")
	decryptedMessage = decrypt(keys['d'],keys['n'],encryptedMessage)
	plaintext = intToStr(decryptedMessage)
	print(plaintext)
	
def main():
	pubKeyF = "public_key.txt";
	privKeyF = "private_key.txt";
	encMsgF = "encrypted_message.txt";
	decMsgF = "decrypted_message.txt";
	encodeOrDecode = -1;
	shouldLoadKeys = -1;
	shouldLoadFromFile = -1;

	print("INSTRUCTIONS: Enter the number corresponding to your choice")
	print("encrypt(1), decrypt(2), or generate keys(3)?")
	encodeOrDecode = int(input())
	
	if (encodeOrDecode == 1):
		print("Load encryption keys from a file(1) or enter in the terminal(2)?")
		shouldLoadKeys = int(input())
		if (shouldLoadKeys == 1):
			print("Enter the public key file name with n and e on the 1st and 2nd lines:")
			inputFile = input()
			inputKeys = readFile(inputFile).splitlines()
			importedN = int(inputKeys[0])
			importedE = int(inputKeys[1])
		else:
			print("Enter n:")
			importedN = int(input())
			print("Enter e:")
			importedE = int(input())
		
		print("Encrypt the message from a file(1) or the terminal(2)?")
		shouldLoadFromFile = int(input())
		
		if (shouldLoadFromFile == 1):
			print("Enter the message's file name:")
			inputFile = input()
			inputMessage = readFile(inputFile)
		else:
			print("Enter your message:")
			inputMessage = input()
		encryptedMessage = encrypt(importedE, importedN, inputMessage)
		
		print("Encrypted message: " + str(encryptedMessage))
		print("Encrypted text stored here: " + str(encMsgF))
		
		writeFile(encMsgF, str(encryptedMessage))

	elif (encodeOrDecode == 2):
		print("Load the decryption key from a file(1) or enter in the terminal(2)?")
		shouldLoadKeys = int(input())
		if (shouldLoadKeys == 1):
			print("Enter the private key file name with n and d on the 1st and 2nd lines:")
			inputFile = input()
			inputKeys = readFile(inputFile).splitlines()
			importedN = int(inputKeys[0])
			importedD = int(inputKeys[1])
		else:
			print("Enter n:")
			importedN = int(input())
			print("Enter d:")
			importedD = int(input())
		
		print("Decrypt a message from a file(1) or the terminal(2)?")
		shouldLoadFromFile = int(input())
		if (shouldLoadFromFile == 1):
			print("Enter the message's file name:")
			inputFile = input()
			inputMessage = readFile(inputFile)
		else:
			print("Enter the encrypted message:")
			inputMessage = int(input())
		decryptedMessage = intToStr(decrypt(importedD, importedN, inputMessage))
		print("Decrypted message: " + decryptedMessage)
		print("Decrypted text stored here: " + decMsgF)
		writeFile(decMsgF, decryptedMessage)

	else:
		print("Generating public/private keys")
		keys = createKeys()
		publickeytext = str(keys['n']) + "\n" + str(keys['e'])
		privatekeytext = str(keys['n']) + "\n" + str(keys['d'])
		writeFile(pubKeyF, publickeytext)
		print("Public keys stored here: " + pubKeyF)
		writeFile(privKeyF, privatekeytext)
		print("Private key stored here: " + privKeyF)

if __name__ == '__main__':
	main()
