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

print("\nServer's public key: %s\n\nServer's private key: %s\n\n" % (public_key, private_key))

with open("serverPK.pem", "wb") as f:
	f.write(public_key)
	f.close()



hostIP = '127.0.0.1'
hostPort = 1234
hostPort1 = 1235
hostPort2 = 1236
keyExchange = False
condition = True
shared_key = ''

def keyExchange():
	global hostIP, hostPort, cipher, keyExchange, shared_key

	with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
		s.bind((hostIP, hostPort))
		s.listen()
		conn,addr = s.accept()
		enmsg = conn.recv(1024)
		shared_key = cipher.decrypt(enmsg, 42).decode()

		#Grab client's public key from the key
		with open("clientPK.pem", "r") as f:
			clientPK = f.read()
			f.close()

		clientPK = RSA.importKey(clientPK)
		cipher2 = PKCS1_v1_5.new(clientPK)
		enmsg = cipher2.encrypt(shared_key.encode())
		conn.send(enmsg)
		response = conn.recv(1024).decode('utf-8')
		if response == "True":
			keyExchange = True
			print("Shared secret key: %s\n" % shared_key)
		else:
			print("Key exchange failed.")
		s.close()

def socket1():
	global condition, hostIP, hostPort1, shared_key

	with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s1:
		s1.bind((hostIP, hostPort1))
		s1.listen()
		conn, addr = s1.accept()
		while condition:
			data = conn.recv(1024)
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
					conn.send(b'Exit')
			except:
				print("Compromised %s %s" % (data[0], data[2]))
				conn.send(b'Exit')
				s1.close()
		print("Connection terminated.")
		s1.close()

def socket2():
	global condition, hostIP, hostPort2, shared_key
	with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s2:
		s2.bind((hostIP, hostPort2))
		s2.listen()
		conn, addr = s2.accept()
		while condition:
			ranBytes = get_random_bytes(12)
			data = input("\n>>> ")
			cipher = AES.new(shared_key.encode(), AES.MODE_CCM, ranBytes)
			ranIV = cipher.encrypt(ranBytes)
			cipher2 = AES.new(shared_key.encode(), AES.MODE_CCM, ranIV)
			enmsg, tag = cipher2.encrypt_and_digest(data.encode())
			print("\nRandom IV: %s\nEncrypted message: %s\nTag: %s\n" % (ranIV, enmsg, tag))
			msg = enmsg + b'@' + ranIV + b'@' + tag
			conn.send(msg)
		print("Connection terminated.")
		conn.send(b'Exit')
		s2.close()


t1 = Thread(target=socket1, args=())
t2 = Thread(target=socket2, args=())
t1.start()
t2.start()
keyExchange()

