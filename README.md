# Secure-Communication
Secure communication between server and client using RSA & CCM for data confidentiality & integrity

Key Exchange Procedures: 
1.	The server opens up a socket and the client connects to that socket. 
2.	The client reads and saves the server’s public key from the file “serverPK.pem”.
3.	The client selects a random string as potential secret key and encrypt that key using server’s public key.
4.	The client sends encrypted secret key to the server. 
5.	Upon receiving the encrypted key, the server decrypts the message using its private key. 
6.	The server encrypts the secret key with client’s public key(accessible to public) and send the encrypted message to client. 
7.	Client decrypts the message using its private key and compare the plaintext with its version of the secret key. If they are the same, the key establish process is successful. Otherwise, terminates the connection.
8.	Simple diagram:
      Client: Encrypt(secret key, server’s public key)
      Client  Server: Ciphertext
      Server: Decrypt(Ciphertext, server’s private key)
      Server: Encrypt(Plaintext, client’s public key)
      Server  Client: Ciphertext
      Client: Decrypt(Ciphertext, client’s private key)
      If Plaintext != secret key: client terminates connection.

Communication Procedures: 
Sender's Perspective: 
1.	The sender generates some random bytes of length 12.
2.	The sender creates a cipher object using the shared secret key and random bytes. The cipher object is in CCM mode using AES encryption.
3.	The sender encrypts those random bytes using the cipher object and the encrypted data will be used as the random IV.
4.	The sender creates another cipher object using the random IV and the shared secret key. The cipher object is in CCM mode using AES encryption. 
5.	The sender encrypts the message and generate a tag(used to ensure data integrity) using the cipher object. 
6.	The sender sends the random IV, encrypted message, and tag to the receiver over the socket. 
7.	Every time a message is intended to be sent, a random IV(which means a new cipher object) will be generated.
8.	Simple diagram:
      Random bytes = generate(12 bytes)
      Cipher = new AES(key=shared secret key, nonce=random bytes)
      Random IV = Cipher.encrypt(Random bytes)
      Another cipher2 = new AES(key=shared secret key, nonce=random IV)
      Ciphertext, tag = cipher2.encrypt_and_digest(plaintext)
      Message = ciphertext + b’@’ + random IV + b’@’ + tag
      Sender  Receiver: Message

Receiver's Perspective: 
1.	The receiver extract random IV from the received data.
2.	The receiver creates a cipher object with the random IV and shared secret key. The cipher object uses CCM mode with AES encryption.
3.	The receiver decrypts and verifies the content and integrity of the data with cipher text and tag. 
4.	If the integrity is compromised, terminates the connection. 
5.	Simple diagram:
      Ciphertext, random IV, tag = message.split(b’@’)
      Cipher = new AES(shared secret key, random IV)
      Plaintext = cipher.decrypt_and_verify(ciphertext, tag)
      If MAC check failed, receiver will terminate the connection
