Course of Action:

Option 2:  start from the v0.5 implementation and to extend it with the security features specified in v1.0.

e.g. begin with SiFTv0.5 and alter its files so the security measures MATCH with v1.0

What needs to be implemented:
- 
- session key establishment (key exchange and key derivation) &
- extending the message transfer protocol with cryptographic functions and replay protection. 

Steps:
-
- read carefully and understand the specification of SiFT v1.0. 
- Then add the required new features to the existing v0.5 implementation. 

Files to modify:
- 
- login.py
- mtp.py
- server.py
- client.py

* generate an RSA key-pair for the server.
  For this, you can write a standalone utility program based on what you did in the corresponding exercise session.
  You should export and save the public key and the key-pair in different files (e.g., in PEM format),
  and put the key-pair file in the server folder and the public key file in the client folder.
* So your server and client programs can read these keys from those files and pass them to the login
  protocol that will use them for the session key establishment. 
