import random
import util
import rsa
import sha1
import socket
from OpenSSL import crypto
import Crypto.PublicKey.RSA
import M2Crypto
import threading


class Client:

    def __init__(self, certificate, user_id, password):

        self.cert = 0  # Client certificate --REPLAY: DON'T KNOW THIS
        self.status = 0  # Status of the connection
        self.server_random = None  # Received server random
        self.client_random = ''  # Generated client random, empty string for easy +='ing
        self.session_id = None  # Received session ID
        self.server_pubkey = 0  # Received sever public key
        self.certificate_required = None  # True if server requires certificate
        self.master_secret = None  # The generated master secret
        self.connection = None  # The connection to the server
        self.userID = user_id  # This client's user ID --REPLAY: DON'T KNOW THIS
        self.password = None  # This client's password --REPLAY: DON'T KNOW THIS
        self.payload_listener = None  # Listener to be called on receiving payload
        self.buffer = bytearray()  # The receive buffer

        self.eavesdropped_data = '030000054d00062d2d2d2d2d424547494e2043455254494649434154452d2d2d2d2d0a4d4949445' \
                                 '37a43434172536741774942416749424254414e42676b71686b6947397730424151734641444342' \
                                 '6d54454c4d416b474131554542684d43516b55780a456a415142674e564241674d4355467564486' \
                                 '46c636e426c626a45534d424147413155454277774a5157353064325679634756754d524d774551' \
                                 '59445651514b0a444170565157353064325679634756754d513877445159445651514c44415a4e5' \
                                 '4314e4253554d78446a414d42674e5642414d4d42573979615739754d5377770a4b67594a4b6f5a' \
                                 '496876634e41516b424668316c6333526c596d46754c6d3131626d6c6a615739416457467564486' \
                                 '46c636e426c626935695a544165467730780a4e6a45784d444d784d6a45774e546861467730784e' \
                                 '7a45784d444d784d6a45774e5468614d49472f4d517377435159445651514745774a43525445534' \
                                 'd4241470a413155454341774a5157353064325679634756754d524977454159445651514844416c' \
                                 '42626e52335a584a775a573478457a415242674e5642416f4d436c56420a626e52335a584a775a5' \
                                 '734784c54417242674e564241734d4a454e766258423164475679494746755a43424f5a58523362' \
                                 '334a7249464e6c59335679615852350a49454e7664584a7a5a5445584d425547413155454177774' \
                                 'f63484a76616d566a6443316a62476c6c626e51784b7a417042676b71686b694739773042435145' \
                                 '570a484842796232706c59335174593278705a57353051485668626e52335a584a775a573475596' \
                                 'd5577675a38774451594a4b6f5a496876634e41514542425141440a675930414d49474a416f4742' \
                                 '414e686236516767556e6f7a366665795458477166676d63465151376a6d766959496f316b54445' \
                                 '5496a615336724e69495533760a6e613134397a5a4f676b5a3774587a615951733159686859762b' \
                                 '44742f6d6d3037734c76567565305a75413933452b4b766b6b305a4c4e33374b3241424557560a7' \
                                 '249534b372f3846716e424c705530704f336c625954696545545177724e6f544235415539654f59' \
                                 '434f75417755376f533668357276467641674d424141476a0a657a42354d416b474131556445775' \
                                 '1434d4141774c41594a59495a49415962345167454e42423857485539775a573554553077675232' \
                                 '56755a584a686447566b0a49454e6c636e52705a6d6c6a5958526c4d42304741315564446751574' \
                                 '242516979636f344b6a6149714f5277653967432b796643556c42766c7a416642674e560a48534d' \
                                 '4547444157674253695179517a2f5864766a6552564e706f6159313534357563374a54414e42676' \
                                 'b71686b6947397730424151734641414f426751425a0a336f375439565044684d31653231592f76' \
                                 '6d4176614850634d684d522f72714479592f76474369646a5641653637562b637472517a6b30723' \
                                 '7736b79366431520a62704139474f6757306546536e7869342b56494350514f537546566933426d' \
                                 '546b4d456f6f784670774f37622f71777168474348663837496d4d73795a79456e0a6236304d5a6' \
                                 '4364c6c45696b6747375542307368756a4d41627550316777686761346e7a384b355556673d3d0a' \
                                 '2d2d2d2d2d454e442043455254494649434154452d2d2d2d2d008069ac9f1eca0bdc2a750ba6b73' \
                                 '49c4a20b802315917786673ed3dbe627a44d022338d53a6b23b6e46367fe7f7c18d1333a36b1fe2' \
                                 '09c4243ef44cd7c738cca707da83fd885aa8ac75e8ae24245b3899459c0fa2c2b3f2a178ff63321' \
                                 'd52246cea0dafd671cdbf3efb942494bc22ac479b8802522a872ab1f24f9842d1531342a1aee25c' \
                                 'd52506aaa50bd185133b105d4bf5e4cf01f0f0'

        self.is_connected = False  # True if there is currently a connection setup to the server

        # Read certificate from file, chop off final newline
        # with open(certificate, 'rt') as f:
        #    self.cert = util.text_to_binary(f.read())
        #    self.cert = self.cert[0:len(self.cert)-1]

        # Get this from eavesdrop instead!
        self.cert = util.hex_string_to_binary(self.eavesdropped_data[14:2420], 1203)

        return

    # Start listening for, processing and replying to connection setup messages
    def process(self, conn):
        print 'Setting up connection...'
        while True:

            buf = conn.recv(4096)
            if not buf:
                break
            bytes_buf = bytearray(buf)

            self.buffer.extend(bytes_buf)  # Add input to receive buffer

            if len(self.buffer) < 5:
                continue # Don't have length yet, can't do anything

            next_length = util.binary_to_int(self.buffer[1:5])

            if len(self.buffer) < next_length + 5:
                continue # Don't have full packet yet, can't do anything

            # Take packet from the receive buffer
            packet = self.buffer[:next_length+5]

            # Decide how to process based on first byte and connection status. Send reply if needed.
            if packet[0] == ord('\x06'):
                error = self.process_error_setup(packet, conn)
                return error
            elif self.status == 2:
                error = self.process_hello(packet, conn)
                if error:
                    self.send_error(conn, error)
                    return error
                conn.send(self.create_key_exchange())
                conn.send(self.create_finished())
                self.status = 5

            elif self.status == 5:
                # Server_finished is encrypted, decrypt first! (first 5 bytes not encrypted)
                if next_length % 24 != 0:
                    #Bad length of encrypted part
                    self.send_error(conn, '\x0A')
                    return
                try:
                    decrypt_buf = util.decrypt_message(packet[5:next_length+5], self.master_secret)
                except:
                    self.send_error(conn, '\x0A')
                    return

                error = self.process_finished(packet[0:5] + decrypt_buf, conn)
                if error:
                    self.send_error(conn, error)
                    return error
                self.status = -1
                self.buffer = self.buffer[next_length+5:]
                print 'Connection setup'
                self.is_connected = True

                # Put payload listener in separate thread, keep main thread available for initiating sends
                listen_thread = threading.Thread(target=self.process_payloads, args=(conn,))
                listen_thread.start()
                return 0 # success
            self.buffer = self.buffer[next_length + 5:]  # Remove processed packet from buffer

    # Start listening for, processing and replying to payload messages
    def process_payloads(self, conn):
        print "Listening for payloads..."
        # skip_recv is true when a packet was processed in the previous recv loop iteration
        # There may be another packet still in the buffer, so attempt to process that immediately
        # instead of waiting for new recv
        skip_recv = False
        while True:
            if not self.is_connected:
                return  # Possible after .disconnect call

            if not skip_recv:
                buf = conn.recv(4096)
                if not buf:
                    break
                bytes_buf = bytearray(buf)
                self.buffer.extend(bytes_buf)  # Add input to receive buffer

            if len(self.buffer) < 5:
                skip_recv = False
                continue # Don't have length yet, can't do anything
            next_length = util.binary_to_int(self.buffer[1:5])

            if len(self.buffer) < next_length + 5:
                skip_recv = False
                continue # Don't have full packet yet, can't do anything

            packet = self.buffer[:next_length+5]

            # Check for error msg before encrypting as they are plain
            if packet[0] == ord('\x06'):
                self.process_error(packet, conn)
                return

            # Definitely encrypted, decrypt everything but first 5 bytes
            try:
                decrypted = packet[0:5] + util.decrypt_message(packet[5:next_length+5], self.master_secret)
            except:
                self.send_error(conn, '\x0A')
                return
            error = self.process_payload(decrypted, conn)
            skip_recv = True
            self.buffer = self.buffer[next_length + 5:]  # Remove processed packet from buffer

    # Process incoming message when server_hello is expected
    def process_hello(self, message, conn):
        print "Received Server Hello"
        if len(message) != 1249:
            return '\x03'
        # Validate some bytes
        message_id = message[0]
        if not util.is_known_message_id(message_id):
            return '\x02'
        if not message[0] == ord('\x02'):
            return '\x01'
        if not message[5] == ord('\x64'):
            return '\x05'
        if not message[6] == ord('\x65'):
            return '\x05'

        # Extract server_random and session ID
        self.server_random = util.binary_to_text(message[7:39])
        self.session_id = message[39:41]

        # Validate some more bytes
        if not (message[41] == ord('\x00') and message[42] == ord('\x2F')):
            return '\x05'
        self.certificate_required = message[43] == ord('\x01')

        # Parse and validate the server certificate
        server_cert = crypto.load_certificate(crypto.FILETYPE_PEM, util.binary_to_text(message[44:1247]))
        if server_cert.get_issuer().commonName != 'orion' or server_cert.has_expired():
            return '\x07'
        # Extract server public key
        self.server_pubkey = Crypto.PublicKey.RSA.importKey(M2Crypto.X509.load_cert_string(message[44:1247]).get_pubkey().as_der())
        # Validate some more bytes
        if not (message[1247] == ord('\xF0') and message[1248] == ord('\xF0')):
            return '\x06'
        return None

    # Process incoming message when server_finished is expected
    def process_finished(self, message, conn):
        print "Received FinishedServer"
        if len(message) < 10:
            return '\x03'
        # Validate some bytes
        message_id = message[0]
        if not util.is_known_message_id(message_id):
            return '\x02'
        if not message[0] == ord('\x05'):
            return '\x01'
        if not message[5:7] == self.session_id:
            return '\x04'
        #skip state
        if not (message[8] == ord('\xF0') and message[9] == ord('\xF0')) :
            return '\x06'
        return None

    # Process incoming error message during  setup phase and close connection
    def process_error_setup(self, message, conn):
        if len(message) != 10:
            print 'Malformed error!'
            return
        print "Received error:", util.get_error_message(message[7])
        conn.close()
        return message[7]

    # Process incoming error message during  setup phase and close connection
    def process_error(self, message, conn):
        print "TODO"
        """if len(message) != 10:
            print 'Malformed error!'
            return
        print "Received error:", util.get_error_message(message[7])
        conn.close()
        return message[7]"""

    # Process incoming payload
    def process_payload(self, message, conn):
        if len(message) < 12:
            print '\x03', None
        # Validate some bytes
        message_id = message[0]
        if not util.is_known_message_id(message_id):
            return '\x02', None
        if not message[0] == ord('\x07'):
            return '\x01', None
        if not message[5:7] == self.session_id:
            return '\x04', None

        # Get the unencrypted payload length
        length = util.binary_to_int(message[7:11])

        if len(message) < 12 + length:
            return '\x03', None
        # Extract the payload
        payload = message[11:11+length]

        if not (message[11+length] == ord('\xF0') and message[12+length] == ord('\xF0')) :
            return '\x06', None

        # If no listener, nothing to do
        if self.payload_listener is None:
            return None, None

        # Generate reply
        reply = self.payload_listener.callback_client(payload, self)
        return None, reply

    # Send an error message with a given error code, and close connection
    def send_error(self, conn, error_code):

        error_message = bytearray(10 * '\x00', 'hex')
        error_message[0] = '\x06'
        error_message[1:5] = util.int_to_binary(5,4)
        if self.session_id:
            error_message[5:7] = self.session_id
        else:
            error_message[5:7] = '\x00\x00' # session ID not yet generated, can't send it
        error_message[7] = error_code
        error_message[8:10] = '\xF0\xF0'

        print 'Sending error:', util.get_error_message(error_message[7])
        conn.send(error_message)
        conn.close()
        return

    # Create a client_hello packet
    def create_hello(self):
        client_hello = bytearray(43 * '\x00', 'hex')
        client_hello[0] = '\x01'
        client_hello[1:5] = util.int_to_binary(38,4)
        client_hello[5] = '\x64'
        client_hello[6] = '\x65'
        # Generate client_random bytes
        for i in range(7,39):
            self.client_random += chr(random.randint(0,255))

        client_hello[7:39] = util.text_to_binary(self.client_random)
        client_hello[39:41] = '\x00\x2F'
        client_hello[41:43] = '\xF0\xF0'
        return client_hello

    # Create a client_key_exchange packet
    def create_key_exchange(self):
        # First generate pre_master
        pre_master = ""
        for _ in range(48):
            pre_master += chr(random.randint(0,127))
        # Encrypt it and get the encrypted length
        pre_master_encrypt = rsa.encrypt_rsa(rsa.text_to_decimal(pre_master), self.server_pubkey.e, self.server_pubkey.n)
        key_length = util.get_length_in_bytes(pre_master_encrypt)

        client_key_exchange = bytearray((1234 + key_length)  * '\x00', 'hex')
        client_key_exchange[0] = '\x03'
        client_key_exchange[1:5] = util.int_to_binary(1229+key_length, 4)
        client_key_exchange[5:7] = self.session_id
        client_key_exchange[7:1210] = self.cert
        client_key_exchange[1210:1212] = util.int_to_binary(key_length, 2)
        client_key_exchange[1212:1212+key_length] = util.int_to_binary(pre_master_encrypt, key_length)
        # -- REPLAY get hashed login info from eavesdrop
        hashed_login = util.hex_string_to_binary(self.eavesdropped_data[-44:-4], 20)
        client_key_exchange[1212+key_length:1232+key_length] = hashed_login
        # client_key_exchange[1212+key_length:1232+key_length] = util.int_to_binary(sha1.sha1(self.userID + self.password), 20)
        client_key_exchange[1232+key_length:1234+key_length] = '\xF0\xF0'

        # Calculate and store the master_secret
        self.master_secret = \
            sha1.sha1(
                sha1.digestToString(sha1.sha1(pre_master + sha1.digestToString(
                    sha1.sha1('A' + pre_master + self.client_random + self.server_random)))) \
                + sha1.digestToString(sha1.sha1(pre_master + sha1.digestToString(
                    sha1.sha1('BB' + pre_master + self.client_random + self.server_random)))) \
                + sha1.digestToString(sha1.sha1(pre_master + sha1.digestToString(
                    sha1.sha1('CCC' + pre_master + self.client_random + self.server_random)))))

        return client_key_exchange

    # Create a client_finished packet
    def create_finished(self):

        client_finished = bytearray(10 * '\x00', 'hex')
        client_finished[0] = '\x04'
        client_finished[1:5] = util.int_to_binary(5, 4)
        client_finished[5:7] = self.session_id
        client_finished[7] = '\x00'
        client_finished[8:10] = '\xF0\xF0'

        return client_finished

    # Open a connection to a server
    def connect(self, host, port):
        self.connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connection.connect((host, port))
        self.connection.send(self.create_hello())
        self.status = 2 # Hello was sent, so status 2
        return self.process(self.connection) # Process will take care of other sends

    # Close the existing connection
    def disconnect(self):
        if self.connection is not None:
            self.is_connected = False
            self.connection.close()

    # Send a payload to the server
    def send_payload(self, payload):
        length = len(payload)
        if length > 4294967200:
            print "payload too big todo"
            return

        # First 5 bytes not encrypted
        client_message = bytearray(5 * '\x00', 'hex')
        client_message[0] = '\x07'

        # Do encrypt the rest
        client_message_to_encrypt = bytearray((8 + length) * '\x00', 'hex')
        client_message_to_encrypt[0:2] = self.session_id
        client_message_to_encrypt[2:6] = util.int_to_binary(length, 4)
        client_message_to_encrypt[6:6 + length] = payload
        client_message_to_encrypt[6 + length:6 + length + 2] = '\xF0\xF0'
        client_message_encrypted = util.encrypt_message(client_message_to_encrypt, self.master_secret)

        # Get length of encrypted part, send concatenation of the two parts
        client_message[1:5] = util.int_to_binary(len(client_message_encrypted), 4)
        self.connection.send(client_message + client_message_encrypted)

    # Set the listener to be called on receiving payload
    def add_payload_listener(self, listener):
        self.payload_listener = listener

# For testing purposes
if __name__ == '__main__':
    client = Client(None, None, None) # --REPLAY: NO ARGS
    error_connect = client.connect('localhost', 8970)
    if error_connect == 0:
        client.send_payload('\x01\x02')
        client.disconnect()


