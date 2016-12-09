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

        self.cert = 0  # Client certificate
        self.status = 0  # Status of the connection
        self.server_random = None  # Received server random
        self.client_random = ''  # Generated client random, empty string for easy +='ing
        self.session_id = -1  # Received session ID
        self.server_pubkey = 0  # Received sever public key
        self.certificate_required = None  # True if server requires certificate
        self.master_secret = None  # The generated master secret
        self.connection = None  # The connection to the server
        self.userID = user_id  # This client's user ID
        self.password = password  # This client's password
        self.payload_listener = None  # Listener to be called on receiving payload
        self.buffer = bytearray()  # The receive buffer

        # Read certificate from file, chop off final newline
        with open(certificate, 'rt') as f:
            self.cert = util.text_to_binary(f.read())
            self.cert = self.cert[0:len(self.cert)-1]
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
                decrypt_buf = util.decrypt_message(packet[5:next_length+5], self.master_secret)

                error = self.process_finished(packet[0:5] + decrypt_buf, conn)
                if error:
                    self.send_error(conn, error)
                    return error
                self.status = -1
                self.buffer = self.buffer[next_length+5:]
                print 'Connection setup', len(self.buffer)

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

            # Definitely encrypted, decrypt everything but first 5 bytes
            packet = self.buffer[0:5] + util.decrypt_message(self.buffer[5:next_length+5], self.master_secret)

            if packet[0] == ord('\x06'):
                error = self.process_error_setup(packet, conn)
                return error

            elif self.status == -1: # receiving payloads
                self.process_payload(packet, conn)

            skip_recv = True
            self.buffer = self.buffer[next_length + 5:]  # Remove processed packet from buffer

    # Process incoming message when server_hello is expected
    def process_hello(self, message, conn):
        print "Received Server Hello"
        if len(message) < 1249:
            print 'todo err'
            return
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
            return '\x06' #todo reset conn
        return None

    # Process incoming message when server_finished is expected
    def process_finished(self, message, conn):
        print "Received FinishedServer"
        if len(message) < 10:
            print 'todo err'
            return
        # Validate some bytes
        message_id = message[0]
        if not util.is_known_message_id(message_id):
            return '\x02'
        if not message[0] == ord('\x04'):
            return '\x01'
        if not message[5:7] == self.session_id:
            return '\x04'
        #skip state
        if not (message[8] == ord('\xF0') and message[9] == ord('\xF0')) :
            return '\x06' #todo reset conn
        return None

    # Process incoming error message during  setup phase and close connection
    def process_error_setup(self, message, conn):
        if len(message) < 10:
            print 'Malformed error!'
            return
        print "Received error:", util.get_error_message(message[7])
        conn.close()
        return message[7]

    # Process incoming payload
    def process_payload(self, message, conn):
        if len(message) < 11:
            print 'todo err'
        # Validate some bytes
        message_id = message[0]
        if not util.is_known_message_id(message_id):
            return '\x02', None
        if not message[0] == ord('\x07'):
            return '\x01', None
        if not message[5:7] == self.session_id:
            return '\x04', None

        # Get the unencrypted payload length
        length = util.binary_to_int(message[7:9])

        if len(message) < 7 + length:
            print 'todo err'
        # Extract the payload
        payload = message[9:9+length]

        if not (message[9+length] == ord('\xF0') and message[10+length] == ord('\xF0')) :
            return '\x06', None #todo reset conn

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
        error_message[5:7] = self.session_id
        error_message[7] = error_code
        error_message[8:10] = '\xF0\xF0'

        print 'Sending error:', error_code, util.get_error_message(error_message[7])
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
        client_key_exchange[1212+key_length:1232+key_length] = util.int_to_binary(sha1.sha1(self.userID + self.password), 20)
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
            self.connection.close()

    # Send a payload to the server
    def send_payload(self, payload):
        length = len(payload)
        if length > 16777000:
            print "payload too big todo"
            return

        # First 5 bytes not encrypted
        client_message = bytearray(5 * '\x00', 'hex')
        client_message[0] = '\x07'

        # Do encrypt the rest
        client_message_to_encrypt = bytearray((6 + length) * '\x00', 'hex')
        client_message_to_encrypt[0:2] = self.session_id
        client_message_to_encrypt[2:4] = util.int_to_binary(length, 2)
        client_message_to_encrypt[4:4 + length] = payload
        client_message_to_encrypt[4 + length:4 + length + 2] = '\xF0\xF0'
        client_message_encrypted = util.encrypt_message(client_message_to_encrypt, self.master_secret)

        # Get length of encrypted part, send concatenation of the two parts
        client_message[1:5] = util.int_to_binary(len(client_message_encrypted), 4)
        self.connection.send(client_message + client_message_encrypted)

    # Set the listener to be called on receiving payload
    def add_payload_listener(self, listener):
        self.payload_listener = listener

# For testing purposes
if __name__ == '__main__':
    client = Client('client-05.pem', 'project-client', 'Konklave123')
    error_connect = client.connect('localhost', 8970)
    print error_connect, "ERROR"
    if error_connect == 0:
        client.send_payload('\x01\x02')


