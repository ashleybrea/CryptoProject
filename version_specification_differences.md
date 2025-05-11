- This is to clearly detail the security difference between v0.5 and v1.0 of SiFT:
  - 
  - Will serve as a reference point while doing the work

What is SiFT?: . SiFT can be used by a client to send file commands to a server, which executes those commands

# SiFT Commands that can be used within a session:
- __pwd__ --> **Print current working directory**: Returns to the client the name of the current working directory on 
              the server.
- 
- __lst__ --> **List content of the current working directory**: Returns to the client the list of files and directories 
              in the current working directory on the server.
- 
- __chd__ --> **Change directory**: Changes the current working directory on the server. The name of the target directory 
              is provided as an argument to the chd command.
- 
- __mkd__ --> **Make directory**: Creates a new directory on the server. The name of the directory to be created is provided
              as an argument to the mkd command.
- 
- __del__ --> **Delete file or directory**: Deletes a file or a directory on the server. The name of the file or directory
              to be deleted is provided as an argument to the del command.
- 
- __upl__ --> **Upload file**: Uploads a file from the client to the server. The name of the file to be uploaded is provided
              as an argument to the upl command and the file is put in the current working directory on the server.
- 
- __dnl__ --> **Download file**: Downloads a file from the current working directory of the server to the client. The name
              of the file to be downloaded is provided as an argument to the dnl command.


SiFT allows the client and the server to communicate via a network and execute the above commands remotely.
It assumes that the client and the server uses the TCP/IP protocol to establish a connection and to send data
reliably to each other. Both v0.5 and v1.0 servers must listen and accept client connection requests on TCP port 5150.

- What does reliability mean? : we mean that the bytes sent by a party arrive to the other party, and they arrive in 
                                the order that they were sent
- 
## Some differences to point out here
    * v.0.5 --> Assumes that the network the client and server are communicating on is SECURE
    * v1.0 ---> does NOT assume that the network is SECURE and provides protection by using a cryptographically secured 
                message transfers sub-protocol. This sub-protocol uses symmetric key cryptographic primitives, and 
                hence, needs shared secret keys. SiFT uses a login sub-protocol to establish the needed secret keys and
                to authenticate the client and the server to each other. In the sequel, we specify these (and other)
                sub-protocols of SiFT v1.0.

## Protocols
```
  +--------------+  +-----------------+  +---------------+  +-----------------+
  |Login Protocol|  |Commands Protocol|  |Upload Protocol|  |Download Protocol|
  +--------------+  +-----------------+  +---------------+  +-----------------+
  +---------------------------------------------------------------------------+
  |                     Message Transfer Protocol (MTP)                       |
  +---------------------------------------------------------------------------+
```
    * v0.5
  - carried by the Message Transfer Protocol (MTP)
  - __Login Protocol__: is used to authenticate the client to the server via a username / password mechanism right 
                        after the establishment of a connection between them. 
  - __Commands Protocol__: is used to send the file commands of the client to the server and the responses to said commands.
  - __Upload Protocol__:   is responsible for the actual upload of the selected file to the server
  - __Download Protocol__: is responsible for the actual download of the selected file from the server.
     

    * v1.0
- carried by the Message Transfer Protocol (MTP)
  - v1.0 of MTP provides cryptographic protection
    - Messages are encrypted, meaning their integrity is protected 
    - sequence numbers are used to detect replay attacks. 
    - MTP uses symmetric key cryptographic primitives ( requires secret keys between the client and the server), which
      are established by the Login Protocol.

  - __Login Protocol__: is used to authenticate the parties to each other and to establish the _secret key_ between the client
                        and the server to be used by MTP. 
    - The _server_ is authenticated implicitly by requiring it to use its private key, 
    - the client authenticates itself to the server by sending a username and a password to it. 
    - The secret key intended for MTP it's derived from random numbers that the client and the server exchange in 
      the Login Protocol.  
      - Since this secret key is established by the Login Protocol, the messages of the Login Protocol itself cannot 
        be protected by this specific key. Hence, MTP uses a temporary key when executing the Login Protocol, which is
        then replaced by the key established by the Login Protocol 
      - The temporary key is generated by the client and it is sent to the server in a login request message, which is 
        encrypted with the server's public key.
      
  - __Commands Protocol__: is used to send the file commands of the client to the server and the responses to said commands.
  - __Upload Protocol__:   is responsible for the actual upload of the selected file to the server
  - __Download Protocol__: is responsible for the actual download of the selected file from the server.
  

### Message Transfer Protocol Differences

    * v0.5
```
	+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
	|  ver  |  typ  |  len  |                                       |
	+---+---+---+---+---+---+                                       +
	|                                                               |
	+                                                               +
	|                                                               |
	.                                                               .
	.                             payload                           .
	.                                                               .
	|                                                               |
	+                                                               +
	|                                                               |
	+               +---+---+---+---+---+---+---+---+---+---+---+---+
	|               |
	+---+---+---+---+
```
- Contains a 6-byte header with:
* ver : A 2-byte _version number_ field. 
        First byte --> is the major version (i.e., 1 in case of v1.0). 
        Second byte --> is the minor version (i.e., 0 in case of v1.0). 
        Meaning that messages conforming this specification must **start** with the byte sequence `01 00`.
* typ : A 2-byte _message type_ field. It  specifies the **type** of the **payload** in the message. 
        Supported message types in v0.5:
    - `00 00` : _login_req_ (login request)
    - `00 10` : _login_res_ (login response)
    - `01 00` : _command_req_ (command request)
    - `01 10` : _command_res_ (command response)
    - `02 00` : _upload_req_0_ (upload request containing a file fragment)
    - `02 01` : _upload_req_1_ (upload request containing the last file fragment)
    - `02 10` : _upload_res_ (upload response)
    - `03 00` : _dnload_req_ (download request)
    - `03 10` : _dnload_res_0_ (download response containing a file fragment)
    - `03 11` : _dnload_res_1_ (download response containing the last file fragment)
* len : A 2-byte _message length_ field. Indicates the length of the entire message (including the header) in
        bytes (using big endian byte order).

* message type value indicators:
  * First byte encodes the type of the interaction between the client and the server
    * `00` --> login
    * `01` --> commands
    * `02` --> upload
    * `03` --> download
  * First nibble of the **second** byte specifies whether the message is a request (a message sent from client
    to server) or a response (a message from server to client). 
    * Requests always have `0`
    * Responses always have `1`
  * The second nibble of the **second** byte differentiates sub-types of a given message type. This is relevant only for
    upload request and download response messages. 
    Files are uploaded to and downloaded from the server in fragments (big chunks, never the entire file at once)
    and sub-types are used to indicate if a message contains:
    * a fragment that will be followed by other fragments --> (value `0`) or,
    * the last fragment of the file --> (value `1`)

* The header is then followed by the payload of any length.

    * v1.0
```
	+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
	|  ver  |  typ  |  len  |  sqn  |          rnd          |  rsv  |
	+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
	|                                                               |
	+                                                               +
	|                                                               |
	.                                                               .
	.                    encrypted payload (epd)                    .
	.                                                               .
	|                                                               |
	+                                                               +
	|                                                               |
	+               +---+---+---+---+---+---+---+---+---+---+---+---+
	|               |                      mac                      |
	+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
```

- Contains a 6-byte header with:
* ver : A 2-byte _version number_ field.
  First byte --> is the major version (i.e., 1 in case of v1.0).
  Second byte --> is the minor version (i.e., 0 in case of v1.0).
  Meaning that messages conforming this specification must **start** with the byte sequence `01 00`.
* typ : A 2-byte _message type_ field. It  specifies the **type** of the **payload** in the message.
  Supported message types in v0.5:
    - `00 00` : _login_req_ (login request)
    - `00 10` : _login_res_ (login response)
    - `01 00` : _command_req_ (command request)
    - `01 10` : _command_res_ (command response)
    - `02 00` : _upload_req_0_ (upload request containing a file fragment)
    - `02 01` : _upload_req_1_ (upload request containing the last file fragment)
    - `02 10` : _upload_res_ (upload response)
    - `03 00` : _dnload_req_ (download request)
    - `03 10` : _dnload_res_0_ (download response containing a file fragment)
    - `03 11` : _dnload_res_1_ (download response containing the last file fragment)
* len : A 2-byte _message length_ field. Indicates the length of the entire message (including the header) in
  bytes (using big endian byte order).
* sqn : A 2-byte _message sequence number_ field. Contains the sequence number of this message
       (using big endian byte order).
* rnd : A 6-byte _random_ field. Contains freshly generated random bytes.
* rsv : A 2-byte _reserved_ field which is NOT USED in this version of the protocol (reserved for future versions). 
  * The value of this field in messages conforming this specification should always be `00 00`.

* message type value indicators:
    * First byte encodes the type of the interaction between the client and the server
        * `00` --> login
        * `01` --> commands
        * `02` --> upload
        * `03` --> download
    * First nibble of the **second** byte specifies whether the message is a request (a message sent from client
      to server) or a response (a message from server to client).
        * Requests always have `0`
        * Responses always have `1`
    * The second nibble of the **second** byte differentiates sub-types of a given message type. This is relevant only for
      upload request and download response messages.
      Files are uploaded to and downloaded from the server in fragments (big chunks, never the entire file at once)
      and sub-types are used to indicate if a message contains:
        * a fragment that will be followed by other fragments --> (value `0`) or,
        * the last fragment of the file --> (value `1`)

* The header is then followed by the AES-GCM enrcrypted payload (__epd__) AND the AES-GCM authentication tag (__mac__). 
  * The mac field in this version of the protocol must be **12 bytes long**. 

* In case of login requests (i.e., message type `00 00`), the message format is different, and it is shown below:

```
	+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
	|  ver  |  typ  |  len  |  sqn  |          rnd          |  rsv  |
	+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
	|                                                               |
	+                                                               +
	|                                                               |
	.                                                               .
	.                    encrypted payload (epd)                    .
	.                                                               .
	|                                                               |
	+                                                               +
	|                                                               |
	+               +---+---+---+---+---+---+---+---+---+---+---+---+
	|               |                      mac                      |
	+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
	|                                                               |
	.                                                               .
	.                encrypted temporary key (etk)                  .
	.                                                               .
	|                                                               |
	+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+	
```

* In case of a login request, the MTP message contains an encrypted temporary key (__etk__)
  following the mac field. 
  * The temporary key is a 32-byte AES key, which is used to produce the encrypted payload (epd)
    and the authentication tag (mac) of the message using AES in GCM mode. 
  * This temporary key is encrypted using RSA-OAEP with a 2048-bit RSA public key. 
    * Thus, the encrypted temporary key (etk) field is 256 bytes (2048 bits) long. 
      * The login request message is sent by the client to the server, and it is produced using a freshly generated temporary key and the
        RSA public key of the server as described below.

            So im curretntly working on a project for my aplied crytography class, where we are given two version of a 
            Simple File Transfer (SiFT). There is version 0.5 -> v0.5, and version 1.0 -> v1.0. My goal is to 
            update the code given to me that repesents SiFT v0.5 to be in line with the security measures (security,
            integrity, etc) of SiFT v1.0

            Key differences:
                - # of inputs varies: (ver, typ, len, sqn, rnd, rsv='00 00')
                - the payload must be encrypted with AES-GCM --> _epd_
                - we also include an AES-GCM encrypted mac, which serves as an authentication tag --> _mac_
                    --> our mac will be 12 bytes long
                - the message transfer protocol is also executed under and if else scenario:
                    -> if the client is submitting a message type that is not of '00 00', e.g. it is not a login 
                       request, then the previous remains true
                    -> if the client is submitting a message type of '00 00', then they are submitting a login
                       request, in this case the message transfer protocol is  bit different, because we then
                       follow the mac with a temporary key, because at this stage our private key has not been
                       established yet, and we want to encrypt the session from the very start.
                              -> the temporary key _etk_ is a 32-byte AES key, that is used to produce the _epd_ and to 
                                 producde the _mac_ using AES-GCM
                              -> the temporary key is also encrypted using RSA-OAEP with a 2048-bit RSA public key
                                 e.g. the encrypted temp key _etk_ is 256 bytes/2048 bits long
### Processing of v1.0 MTP

SiFT allows the client and the server to communicate via a network and execute the established commands remotely.
Assumes to use TCP/IP protocol to establish a connection and to send data back and forth. 
Both v0.5 and v1.0 servers must listen and accept client connection requests on TCP port 5150.

When the TCP port 5150 connection is established:
    1. The client sends a login request message type -> `00 00`
        a.  In order to carry out this message, MTP generates a fresh 6-byte random value _r_ and a fresh 32-byte
            random temporary key _tk_ using a cryptographic random number generator, and the message header
            variables are filled in like this:
            * ver = `01 00` ~~ `because this is v1.0`
            * typ = `00 00` ~~ `because this is a login request msg type`
            * len is calculated as the sum of the length of the header (16), the length of the encrypted payload 
                (same as the length of the payload), the length of the mac field (12), and the length of the encrypted 
                temporary key (256)
            * sqn = `00 01` ~~ `i.e., message sequence numbering is started from 1`
            * rnd = r ~~ `(i.e., the 6-byte fresh random value generated before)`
            * rsv = `00 00` ~~ `will always be this bc this isnt implement in v1.0`
        b. then we encrypt the payload of the login response AND produce the authentication tag _mac_ on the message header
            --> The client and the server also send random values: client_random and server_random in the payload of the
                login request and login response messages, and they use these random numbers to create the final 
                transfer key that will be used in the rest of the session. 
                If the login was successful, then the temporary key used to protect the login messages is discarded, 
                and both the client and the server set the transfer key to be the value derived from client_random
                and server_random. All subsequent messages will be protected with this final transfer key. The sequence 
                numbers are not reset.
        c. then the encrypted payload (in AES-GCM) with _tk_ as the key and sqn+rnd (concatenate) as the nonce
            --> this is how the _epd_ and _mac_ are produced
            --> THEN all fields are filled and login response is sent to client

    2. All MTP messages after the login request message will be produced as previosuly described

    3. For the login response message ( server to client )
        a. the message header is produced with the appropriate message type (depending on the payload to be sent), 
           length, the next sending sequence number, and a _fresh_ 6-byte random value,
        b. the encrypted payload and the mac fields are produced by processing the message header and the payload with 
            AES in GCM mode using the final transfer key as the key and sqn+rnd as the nonce,
        c. the message is sent and the incremented sending sequence number is stored (as the sequence number of the last
            message sent).
    
    4. When a MTP message is receieved, the receiving party (either client or server):
        a. verifies if the sequence number sqn in the message is larger than the last received sequence number, 
        b. verifies the _mac_ and decrypts the encrypted payload with AES in GCM mode using the final _transfer key_ as 
            the key and sqn+rnd as the nonce, and
        c. if all verifications are successful, the stored receiving sequence number is set to the sqn value received in the
            message header.
                --> In the case that a a message that does not pass all verifications, it must be silently discarded,
                (e.g. no error message is sent in the MTP protocol) and the connection between the client and the server 
                must be closed after it is detected. Closing the connection is initiated by the receiving party that 
                encountered the offending message.






