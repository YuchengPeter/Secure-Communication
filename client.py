#!/usr/bin/python3

import socket
from threading import *
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Hash import CMAC
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

new_key = RSA.generate(4096, e=65537)
private_key = new_key.export_key()
public_key = new_key.publickey().exportKey("PEM")
cipher = PKCS1_v1_5.new(new_key)

print("\nClient's public key: %s\n\nClient's private key: %s\n\n" % (public_key, private_key))

with open("clientPK.pem", "wb") as f:
	f.write(public_key)
	f.close()


serverIP = '127.0.0.1'
serverPort = 1234
serverPort1 = 1235
serverPort2 = 1236
keyExchange = False
condition = True
shared_key = ''

def keyExchange():
	global condition, serverIP, serverPort, shared_key
	shared_key = "a randome key ha"

	#Grab server's public key
	with open("serverPK.pem", "r") as f:
		serverPK = f.read()
		f.close()
	
	serverPK = RSA.importKey(serverPK)
	with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
		s.connect((serverIP, serverPort))
		cipher1 = PKCS1_v1_5.new(serverPK)
		enmsg = cipher1.encrypt(shared_key.encode())
		s.send(enmsg)
		response = s.recv(1024)
		recvKey = cipher.decrypt(response, 42).decode()
		if recvKey == shared_key:
			keyExchange = True
			s.send(b"True")
			print("Shared secret key: %s\n" % shared_key)
		else:
			keyExchange = False
		s.close()

def socket1():
	global condition, serverIP, serverPort1, shared_key
	with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s1:
		s1.connect((serverIP, serverPort1))
		while condition:
			data = input("\n>>> ")
			ranBytes = get_random_bytes(12)
			cipher = AES.new(shared_key.encode(), AES.MODE_CCM, ranBytes)
			ranIV = cipher.encrypt(ranBytes)
			cipher2 = AES.new(shared_key.encode(), AES.MODE_CCM, ranIV)
			enmsg, tag = cipher2.encrypt_and_digest(data.encode())
			print("\nRandom IV: %s\nEncrypted message: %s\nTag: %s\n" % (ranIV, enmsg, tag))
			msg = enmsg + b'@' + ranIV + b'@' + tag
			s1.send(msg)
		print("Connection terminated.")
		s1.send(b'Exit')
		s1.close()

def socket2():
	global condition, serverIP, serverPort2, shared_key

	with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s2:
		s2.connect((serverIP, serverPort2))

		while condition:
			data = s2.recv(1024)
			data = data.split(b"@")
			try: 
				msg = data[0]
				ranIV = data[1]
				tag = data[2]
				cipher = AES.new(shared_key.encode(), AES.MODE_CCM, ranIV)
				demsg = cipher.decrypt_and_verify(msg, tag)
				demsg = demsg.decode()
				print('\nRandom IV: %s\nDecrypted message: %s\nTag: %s\n  ' % (ranIV, demsg, tag))
				if demsg == "Exit":
					condition = False
					s2.send(b'Exit')
			except:
				print("Compromised")
				s2.send(b'Exit')
				s2.close()
		print("Connection terminated.")
		s2.close()


keyExchange()

if keyExchange:
	t1 = Thread(target=socket1, args=())
	t2 = Thread(target=socket2, args=())
	t1.start()
	t2.start()
