#python3

import socket
import secrets
import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP

class SiFT_MTP_Error(Exception):

    def __init__(self, err_msg):
        self.err_msg = err_msg

class SiFT_MTP:
    def __init__(self, peer_socket):

        self.DEBUG = True
        # --------- CONSTANTS ------------
        # Changed the version numbers
        self.version_major = 1
        self.version_minor = 0

        # Change header version
        self.msg_hdr_ver = b'\x01\x00'

        # Change length of the header
        self.size_msg_hdr = 16

        self.size_msg_hdr_ver = 2
        self.size_msg_hdr_typ = 2
        self.size_msg_hdr_len = 2

        # Add new fields
        self.size_msg_hdr_sqn = 2
        self.size_msg_hdr_rnd = 6
        self.size_msg_hdr_rsv = 2

        # New field to store the final_transfer_key
        self.final_transfer_key = b''

        self.server_decrypted_tk = b''
        self.client_saved_tk = b''

        self.type_login_req =    b'\x00\x00'
        self.type_login_res =    b'\x00\x10'
        self.type_command_req =  b'\x01\x00'
        self.type_command_res =  b'\x01\x10'
        self.type_upload_req_0 = b'\x02\x00'
        self.type_upload_req_1 = b'\x02\x01'
        self.type_upload_res =   b'\x02\x10'
        self.type_dnload_req =   b'\x03\x00'
        self.type_dnload_res_0 = b'\x03\x10'
        self.type_dnload_res_1 = b'\x03\x11'
        self.msg_types = (self.type_login_req, self.type_login_res,
                          self.type_command_req, self.type_command_res,
                          self.type_upload_req_0, self.type_upload_req_1, self.type_upload_res,
                          self.type_dnload_req, self.type_dnload_res_0, self.type_dnload_res_1)
        # --------- STATE ------------
        self.peer_socket = peer_socket
        self.sqn_num_send = 0
        self.sqn_num_recv = -1


    # parses a message header and returns a dictionary containing the header fields
    def parse_msg_header(self, msg_hdr):

        parsed_msg_hdr, i = {}, 0
        parsed_msg_hdr['ver'], i = msg_hdr[i:i+self.size_msg_hdr_ver], i+self.size_msg_hdr_ver
        parsed_msg_hdr['typ'], i = msg_hdr[i:i+self.size_msg_hdr_typ], i+self.size_msg_hdr_typ

        # Parse new header fields
        parsed_msg_hdr['len'], i = msg_hdr[i:i+self.size_msg_hdr_len], i+self.size_msg_hdr_len
        parsed_msg_hdr['sqn'], i = msg_hdr[i:i+self.size_msg_hdr_sqn], i+self.size_msg_hdr_sqn
        parsed_msg_hdr['rnd'], i = msg_hdr[i:i+self.size_msg_hdr_rnd], i+self.size_msg_hdr_rnd
        parsed_msg_hdr['rsv'], i = msg_hdr[i:i+self.size_msg_hdr_rsv]
        return parsed_msg_hdr


    # receives n bytes from the peer socket
    def receive_bytes(self, n):

        bytes_received = b''
        bytes_count = 0
        while bytes_count < n:
            try:
                chunk = self.peer_socket.recv(n-bytes_count)
            except:
                raise SiFT_MTP_Error('Unable to receive via peer socket')
            if not chunk:
                raise SiFT_MTP_Error('Connection with peer is broken')
            bytes_received += chunk
            bytes_count += len(chunk)
        return bytes_received


    # receives and parses message, returns msg_type and msg_payload
    def receive_msg(self):
        print("!New message received!")
        print("-----------------------")
        try:
            msg_hdr = self.receive_bytes(self.size_msg_hdr)
        except SiFT_MTP_Error as e:
            raise SiFT_MTP_Error('Unable to receive message header --> ' + e.err_msg)

        if len(msg_hdr) != self.size_msg_hdr:
            raise SiFT_MTP_Error('Incomplete message header received')
        
        parsed_msg_hdr = self.parse_msg_header(msg_hdr)

        if parsed_msg_hdr['ver'] != self.msg_hdr_ver:
            raise SiFT_MTP_Error('Unsupported version found in message header')

        if parsed_msg_hdr['typ'] not in self.msg_types:
            raise SiFT_MTP_Error('Unknown message type found in message header')
        
        # validating sqn number
        msg_sqn_int = int.from_bytes(parsed_msg_hdr['sqn'], byteorder='big')
        expected_sqn_num = (self.sqn_num_recv + 1) % 65536
        # TODO: remove error raising and instead implement disconnecting session
        if msg_sqn_int != expected_sqn_num:
            raise SiFT_MTP_Error("unexpected sqn #")
        self.sqn_num_recv = msg_sqn_int

        msg_len = int.from_bytes(parsed_msg_hdr['len'], byteorder='big') # AB

        # Handle the login request
        if parsed_msg_hdr['typ'] == self.type_login_req:
            print("Login request received...")
            msg_len = int.from_bytes(parsed_msg_hdr['len'], byteorder='big')

            # TODO: Need to check sequence number
            msg_sqn = int.from_bytes(parsed_msg_hdr['sqn'], byteorder='big')

            msg_body = self.receive_bytes(msg_len - self.size_msg_hdr)
            etk = msg_body[-256:]
            
            # Decrypting the etk
            rsa_private_key = self.server_load_rsa_keys()[1]
            cipher_rsa = PKCS1_OAEP.new(rsa_private_key)
            decrypted_tk = cipher_rsa.decrypt(etk)
            self.server_decrypted_tk = decrypted_tk

            mac = msg_body[-268:-256]
            nonce = parsed_msg_hdr['sqn'] + parsed_msg_hdr['rnd']
            ciphertext = msg_body[:-268]
            aes_decipher = AES.new(key = decrypted_tk, mode=AES.MODE_GCM, nonce=nonce, mac_len= 12)
            aes_decipher.update(msg_hdr)

            try:
                plaintext = aes_decipher.decrypt_and_verify(ciphertext, mac)
                print("MAC of the login request had been verified!")
                print("---------------------------------------------")

                if self.DEBUG:
                    print('MTP message received (' + str(msg_len) + '):\n')
                    print('HDR (' + str(len(msg_hdr)) + '): ' + msg_hdr.hex())
                    print('EPD (' + str(len(ciphertext)) + '): \n' + ciphertext.hex())
                    print('MAC (' + str(len(mac)) + '): \n' + mac.hex())
                    print('ETK (' + str(len(etk)) + '): \n' + etk.hex())
                    print('------------------------------------------')
                    print("Login request received")
                return parsed_msg_hdr['typ'], plaintext
            except ValueError:
                print("MAC verification failed!")
        elif parsed_msg_hdr['typ'] == self.type_login_res:
            print("Login response received...")
            msg_len = int.from_bytes(parsed_msg_hdr['len'], byteorder='big')

            # TODO: Need to check sequence number
            msg_sqn = int.from_bytes(parsed_msg_hdr['sqn'], byteorder='big')

            msg_body = self.receive_bytes(msg_len - self.size_msg_hdr)

            mac = msg_body[-12:]
            print("received login res mac: ", mac.hex())
            tk = self.client_saved_tk
            nonce = parsed_msg_hdr['sqn'] + parsed_msg_hdr['rnd']
            ciphertext = msg_body[:-12]
            aes_decipher = AES.new(key = tk, mode=AES.MODE_GCM, nonce=nonce, mac_len= 12)
            aes_decipher.update(msg_hdr)
            try:
                plaintext = aes_decipher.decrypt_and_verify(ciphertext, mac)
                print("MAC of the login response had been verified!")
                print("---------------------------------------------")

                if self.DEBUG:
                    print('MTP message received (' + str(msg_len) + '):\n')
                    print('HDR (' + str(len(msg_hdr)) + '): ' + msg_hdr.hex())
                    print('EPD (' + str(len(ciphertext)) + '): \n' + ciphertext.hex())
                    print('MAC (' + str(len(mac)) + '): \n' + mac.hex())
                    print('------------------------------------------')
                    print("Login response received")
                    print("Final transfer key: ", self.final_transfer_key)
                return parsed_msg_hdr['typ'], plaintext
            except ValueError:
                print("MAC verification failed!")
        else:
            msg_len = int.from_bytes(parsed_msg_hdr['len'], byteorder='big')

            # TODO: Need to check sequence number
            msg_sqn = int.from_bytes(parsed_msg_hdr['sqn'], byteorder='big')

            try:
                msg_body = self.receive_bytes(msg_len - self.size_msg_hdr)
            except SiFT_MTP_Error as e:
                raise SiFT_MTP_Error('Unable to receive message body --> ' + e.err_msg)
            
            if len(msg_body) != msg_len - self.size_msg_hdr:
                raise SiFT_MTP_Error('Incomplete message body received')
            
            mac = msg_body[-12:]
            nonce = parsed_msg_hdr['sqn'] + parsed_msg_hdr['rnd']
            ciphertext = msg_body[:-12]
            aes_decipher = AES.new(key = self.final_transfer_key, mode=AES.MODE_GCM, nonce=nonce, mac_len= 12)
            aes_decipher.update(msg_hdr)

            try:
                plaintext = aes_decipher.decrypt_and_verify(ciphertext, mac)
                print("MAC of the (other)message had been verified!")
                print("---------------------------------------------")

                if self.DEBUG:
                    print('MTP message received (' + str(msg_len) + '):\n')
                    print('HDR (' + str(len(msg_hdr)) + '): ' + msg_hdr.hex())
                    print('EPD (' + str(len(ciphertext)) + '): \n' + ciphertext.hex())
                    print('MAC (' + str(len(mac)) + '): \n' + mac.hex())
                    print('------------------------------------------')
                    return parsed_msg_hdr['typ'], plaintext
            except ValueError:
                print("MAC verification failed!")
            
    # sends all bytes provided via the peer socket
    def send_bytes(self, bytes_to_send):
        try:
            self.peer_socket.sendall(bytes_to_send)
        except:
            raise SiFT_MTP_Error('Unable to send via peer socket')

    # builds and sends message of a given type using the provided payload
    def send_msg(self, msg_type, msg_payload):
        # build message
        msg_size = self.size_msg_hdr + len(msg_payload)
        msg_hdr_len = msg_size.to_bytes(self.size_msg_hdr_len, byteorder='big')

        # msg_sqn = 0
        msg_sqn_int = self.sqn_num_send
        msg_sqn = msg_sqn_int.to_bytes(2, byteorder='big')  # 2 bytes, cur sqn number
        self.sqn_num_send = (self.sqn_num_send + 1) % 65536 # increment

        msg_rnd = secrets.token_bytes(6)
        msg_rsv = b'\x00\x00'
        msg_hdr = self.msg_hdr_ver + msg_type + msg_hdr_len + msg_sqn + msg_rnd + msg_rsv

        # All necessary steps to build and send a login request
        if msg_type == self.type_login_req:
            print ("Building login request...")
            msg_size = self.size_msg_hdr + len(msg_payload) + 12 + 256
            msg_hdr_len = msg_size.to_bytes(self.size_msg_hdr_len, byteorder='big')
            msg_hdr = self.msg_hdr_ver + msg_type + msg_hdr_len + msg_sqn + msg_rnd + msg_rsv

            tk = secrets.token_bytes(32)
            self.client_saved_tk = tk
            cipher = AES.new(key=tk, mode=AES.MODE_GCM, nonce= msg_sqn + msg_rnd, mac_len=12)
            cipher.update(msg_hdr)
            ciphertext, tag = cipher.encrypt_and_digest(msg_payload)

            # add to message payload
            msg_payload = ciphertext + tag

            # add encrypted temporary key
            rsa_public_key = self.client_load_rsa_key()
            rsa_cipher = PKCS1_OAEP.new(rsa_public_key)
            etk = rsa_cipher.encrypt(tk)
            msg_payload = msg_payload + etk

            if self.DEBUG:
                print('MTP message to send (' + str(msg_size) + '):')
                print('HDR (' + str(len(msg_hdr)) + '): ' + msg_hdr.hex())
                print('EPD (' + str(len(ciphertext)) + '): \n' + ciphertext.hex())
                print('MAC (' + str(len(tag)) + '): \n' + tag.hex())
                print('ETK (' + str(len(etk)) + '): \n' + etk.hex())
                print('------------------------------------------')

        elif msg_type == self.type_login_res:
            print("Building login response...")
            msg_size = self.size_msg_hdr + len(msg_payload) + 12
            msg_hdr_len = msg_size.to_bytes(self.size_msg_hdr_len, byteorder='big')
            msg_hdr = self.msg_hdr_ver + msg_type + msg_hdr_len + msg_sqn + msg_rnd + msg_rsv

            tk = self.server_decrypted_tk
            cipher = AES.new(key=tk, mode=AES.MODE_GCM, nonce= msg_sqn + msg_rnd, mac_len=12)
            cipher.update(msg_hdr)
            ciphertext, tag = cipher.encrypt_and_digest(msg_payload)
            # add to message payload
            msg_payload = ciphertext + tag

            if self.DEBUG:
                print('MTP message to send (' + str(msg_size) + '):')
                print('HDR (' + str(len(msg_hdr)) + '): ' + msg_hdr.hex())
                print('EPD (' + str(len(ciphertext)) + '): \n' + ciphertext.hex())
                print('MAC (' + str(len(tag)) + '): \n' + tag.hex())
                print('------------------------------------------')
        else:
            msg_size = self.size_msg_hdr + len(msg_payload) + 12
            msg_hdr_len = msg_size.to_bytes(self.size_msg_hdr_len, byteorder='big')
            msg_hdr = self.msg_hdr_ver + msg_type + msg_hdr_len + msg_sqn + msg_rnd + msg_rsv

            cipher = AES.new(key=self.final_transfer_key, mode=AES.MODE_GCM, nonce= msg_sqn + msg_rnd, mac_len=12)
            cipher.update(msg_hdr)
            ciphertext, tag = cipher.encrypt_and_digest(msg_payload)
            # add to message payload
            msg_payload = ciphertext + tag

            if self.DEBUG:
                print('MTP message to send (' + str(msg_size) + '):')
                print('HDR (' + str(len(msg_hdr)) + '): ' + msg_hdr.hex())
                print('EPD (' + str(len(ciphertext)) + '): \n' + ciphertext.hex())
                print('MAC (' + str(len(tag)) + '): \n' + tag.hex())
                print('------------------------------------------')
            



        # # DEBUG
        # if self.DEBUG:
        #     print('MTP message to send (' + str(msg_size) + '):')
        #     print('HDR (' + str(len(msg_hdr)) + '): ' + msg_hdr.hex())
        #     print('BDY (' + str(len(msg_payload)) + '): ')
        #     print(msg_payload.hex())
        #     print('------------------------------------------')
        # # DEBUG

        # try to send
        try:
            self.send_bytes(msg_hdr + msg_payload)
        except SiFT_MTP_Error as e:
            raise SiFT_MTP_Error('Unable to send message to peer --> ' + e.err_msg)

    #--------------------------NEW HELPER FUNCITONS-------------------------------#
    
    # setter for the final transfer key
    def set_final_transfer_key(self, final_transfer_key):
        self.final_transfer_key = final_transfer_key

    # setter for the sha 256 calculated by the client
    def set_client_sha_256(self, client_sha_256):
        self.client_sha_256 = client_sha_256
    
    # setter for the sha 256 calculated by the server
    def set_server_sha_256(self, server_sha_256):
        self.server_sha_256 = server_sha_256

    # loads and returns the public rsa key
    def client_load_rsa_key(self):
        parent_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
        public_key_path = os.path.join(parent_dir, 'public_key.pem')
        with open(public_key_path, 'rb') as f:
            public_key = RSA.import_key(f.read())
        return public_key
    
    # loads and returns the rsa key pair, both the public and private key
    def server_load_rsa_keys(self):
        parent_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
        public_key_path = os.path.join(parent_dir, 'public_key.pem')
        with open(public_key_path, 'rb') as f:
            public_key = RSA.import_key(f.read())
    
        private_key_path = os.path.join(parent_dir, 'private_key.pem')
        with open(private_key_path, 'rb') as f:
            private_key = RSA.import_key(f.read(), passphrase="rsa_key")
        
        return public_key, private_key
    
# def main():
#     myMTP = SiFT_MTP(200)
#     print(myMTP.server_load_rsa_keys()[0].export_key().decode())

# if __name__ == "__main__":
#     main()



