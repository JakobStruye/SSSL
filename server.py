import random
import util
import socket
import threading
import sha1
import rsa
from OpenSSL import crypto
import Crypto.PublicKey.RSA
import M2Crypto


class Server:

    def __init__(self, certificate, key):

        self.cert = 0  # Server certificate
        self.private_key = 0  # Server private key
        self.max_server_id = 0  # Next session ID to assign
        self.connections = list()  # All current connections

        # All these dicts are indexed by connection objects
        self.statuses = dict() # Status of each current connection
        self.client_randoms = dict()  # All received client randoms
        self.server_randoms = dict()  # All generated server randoms
        self.client_pubkeys = dict()  # All received client pubkeys
        self.master_secrets = dict()  # All generated master secrets
        self.session_ids = dict()  # All generated session IDs
        self.user_ids = dict()  # All received user IDs
        self.buffers = dict()  # All current receive buffers

        self.accounts = dict()  # The registered user accounts, mapping user ID to user ID + password hash
        self.payload_listener = None  # The current payload listener, to be called on receiving payload

        # Read certificate from file
        with open(certificate, 'rt') as f:
            self.cert = util.text_to_binary(f.read())
            self.cert = self.cert[0:len(self.cert)-1]

        # Read private key from file
        with open(key, 'rt') as f:
            self.private_key = Crypto.PublicKey.RSA.importKey(f.read())

    # Add an allowed account
    def add_account(self, username, password):
        self.accounts[username] = sha1.sha1(username+password)

    # Add an allowed account, with userID + password already hashed
    def add_account_hashed(self, username, digest):
        self.accounts[username] = digest

    # Start the server
    def start(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind(('0.0.0.0', 8970))  # 0.0.0.0 allows outside connections
        server_socket.listen(1024)  # become a server socket, maximum 1024 connections

        # Start thread dedicated to listening for NEW connections
        listen_thread = threading.Thread(target=self.listen, args=(server_socket,))
        listen_thread.start()

        return

    # Listen for NEW incoming connections
    def listen(self, server_socket):
        while True:
            print 'Listening for new connection...'
            conn, address = server_socket.accept()
            self.connections.append(conn)
            self.statuses[conn] = 1
            # Start new thread for every new connection
            process_thread = threading.Thread(target=self.process_setup, args=(conn,))
            process_thread.start()

    # Process incoming packets for connection in SSL setup phase
    def process_setup(self, conn):
        self.buffers[conn] = bytearray()  # Start with empty buffer
        print 'Setting up new connection...'

        # skip_recv is true when a packet was processed in the previous recv loop iteration
        # There may be another packet still in the buffer, so attempt to process that immediately
        # instead of waiting for new recv
        skip_recv = False
        while True:
            if not skip_recv:
                buf = conn.recv(4096)  # Changing this does not break the process
                if not buf:
                    break
                bytes_buf = bytearray(buf)
                self.buffers[conn].extend(bytes_buf)  # Add input to receive buffer
            if len(self.buffers[conn]) < 5:
                skip_recv = False  # Wait for receive next iteration
                continue  # Don't have length yet, can't do anything

            next_length = util.binary_to_int(self.buffers[conn][1:5])

            if len(self.buffers[conn]) < next_length + 5:
                skip_recv = False  # Wait for receive next iteration
                continue  # Don't have full packet yet, can't do anything

            # Take one packet from the receive buffer
            packet = self.buffers[conn][:next_length+5]

            # Decide how to process based on first byte and connection status. Send reply if needed.
            if packet[0] == ord('\x06'):
                self.process_error_setup(packet, conn)
                return

            elif self.statuses[conn] == 1:
                error = self.process_hello(packet, conn) # Should only receive this now
                if error:
                    self.send_error(conn, error)
                    return
                else:
                    conn.send(self.create_hello(conn))
                    self.statuses[conn] = 3
            elif self.statuses[conn] == 3:
                error = self.process_key_exchange(packet, conn)
                if error:
                    self.send_error(conn, error)
                    return
                else:
                    self.statuses[conn] = 4
                    # No reply, wait for client_finished
            elif self.statuses[conn] == 4:
                error = self.process_finished(packet, conn)
                if error:
                    self.send_error(conn, error)
                    return
                else:
                    conn.send(self.create_finished(conn))
                    self.statuses[conn] = -1 # means setup complete
                    print 'Connection setup'
                    self.buffers[conn] = self.buffers[conn][next_length + 5:]  # Remove processed packet from buffer
                    self.process_payloads(conn)
                    return

            skip_recv = True
            self.buffers[conn] = self.buffers[conn][next_length+5:]  # Remove processed packet from buffer

    # Process incoming packets for secure connection
    def process_payloads(self, conn):
        print 'Listening for payloads...'

        # skip_recv is true when a packet was processed in the previous recv loop iteration
        # There may be another packet still in the buffer, so attempt to process that immediately
        # instead of waiting for new recv
        skip_recv = False
        while True:
            if not skip_recv:
                buf = conn.recv(4096)  # Changing this does not break the process
                if not buf:
                    break
                bytes_buf = bytearray(buf)
                self.buffers[conn].extend(bytes_buf)  # Add input to receive buffer
            if len(self.buffers[conn]) < 5:
                skip_recv = False  # Wait for receive next iteration
                continue  # Don't have length yet, can't do anything

            next_length = util.binary_to_int(self.buffers[conn][1:5])

            if len(self.buffers[conn]) < next_length + 5:
                skip_recv = False  # Wait for receive next iteration
                continue  # Don't have full packet yet, can't do anything

            # Take one packet from the receive buffer
            packet = self.buffers[conn][:next_length+5]

            # Check for error msg before encrypting as they are plain
            if packet[0] == ord('\x06'):
                self.process_error(packet, conn)
                return

            # The first 5 bytes are not decrypted, decrypt the rest using right master secret
            try:
                decrypted = packet[0:5] + util.decrypt_message(packet[5:next_length+5], self.master_secrets[conn])
            except:
                self.send_error(conn, '\x0A')
                return

            # Process and send any error or replies generated
            error, replies = self.process_payload(decrypted, conn)
            if error:
                self.send_error(conn, error)
                return

            elif replies:
                for reply in replies:
                    reply_packet = self.create_payload(reply, conn)
                    conn.send(reply_packet)

            skip_recv = True
            self.buffers[conn] = self.buffers[conn][next_length+5:]  # Removed processed packet from buffer

    # Process incoming message when client_hello is expected
    def process_hello(self, message, conn):
        print "Received ClientHello"
        if len(message) != 43:
            return '\x03'
        message_id = message[0]
        # Validate some bytes
        if not util.is_known_message_id(message_id):
            return '\x02'
        if not message[0] == ord('\x01'):
            return '\x01'
        if not message[5] == ord('\x64'):
            return '\x05'
        if not message[6] == ord('\x65'):
            return '\x05'
        # Extract client_random
        self.client_randoms[conn] = util.binary_to_text(message[7:39])
        # Validate some more bytes
        if not (message[39] == ord('\x00') and message[40] == ord('\x2F')):
            return '\x05'
        if not (message[41] == ord('\xF0') and message[42] == ord('\xF0')):
            return '\x06'
        return None

    # Process incoming message when client_key_exchange is expected
    def process_key_exchange(self, message, conn):
        print "Received ClientKeyExchange"
        if len(message) < 1234:
            return '\x03'
        # Validate some bytes
        message_id = message[0]
        if not util.is_known_message_id(message_id):
            return '\x02'
        if not message[0] == ord('\x03'):
            return '\x01'
        if not message[5:7] == self.session_ids[conn]:
            return '\x04'

        # Parse and validate certificate
        client_cert = crypto.load_certificate(crypto.FILETYPE_PEM, util.binary_to_text(message[7:1210]))
        if client_cert.get_issuer().commonName != 'orion' or client_cert.has_expired() :
            return '\x08'
        # Extract pubkey from certificate
        self.client_pubkeys[conn] = Crypto.PublicKey.RSA.importKey(M2Crypto.X509.load_cert_string(message[7:1210]).get_pubkey().as_der())

        # Extract and decrypt pre_master
        length = util.binary_to_int(message[1210:1212])

        if len(message) != 1234 + length:
            return '\x03'

        pre_master = rsa.long_to_text(rsa.decrypt_rsa(util.binary_to_long(message[1212:1212+length]), self.private_key.d, self.private_key.n), 48)

        # Validate login
        user_id = client_cert.get_subject().commonName
        if not message[1212+length:1232+length] == util.int_to_binary(self.accounts[user_id], 20):
            return '\x09'
        self.user_ids[conn] = user_id
        # Validate some bytes
        if not (message[1232+length] == ord('\xF0') and message[1233+length] == ord('\xF0')) :
            return '\x06'

        # Now knows enough to calculate master secret
        server_random = self.server_randoms[conn]
        client_random = self.client_randoms[conn]

        master_secret = \
            sha1.sha1(
                sha1.digestToString(sha1.sha1(
                    pre_master + sha1.digestToString(sha1.sha1('A' + pre_master + client_random + server_random)))) \
                + sha1.digestToString(sha1.sha1(
                    pre_master + sha1.digestToString(sha1.sha1('BB' + pre_master + client_random + server_random)))) \
                + sha1.digestToString(sha1.sha1(
                    pre_master + sha1.digestToString(sha1.sha1('CCC' + pre_master + client_random + server_random)))))

        self.master_secrets[conn] = master_secret

        return None

    # Process incoming packet when client_finished is expected
    def process_finished(self, message, conn):
        print "Received FinishedClient"
        if len(message) != 10:
            return '\x03'
        # Validate some bytes
        message_id = message[0]
        if not util.is_known_message_id(message_id):
            return '\x02'
        if not message[0] == ord('\x04'):
            return '\x01'
        if not message[5:7] == self.session_ids[conn]:
            return '\x04'
        #skip state
        if not (message[8] == ord('\xF0') and message[9] == ord('\xF0')) :
            return '\x06'
        return None

    # Process error message received during setup phase and close connection
    def process_error(self, message, conn):
        #MAY ALSO BE FROM LATE SETUP
        print 'todo err'
        if len(message) != 10:
            print 'Malformed error!'
            return
        print "Received error:", util.get_error_message(message[7])
        conn.close()
        return

    # Process error message received during setup phase and close connection
    def process_error_setup(self, message, conn):
        if len(message) != 10:
            print 'Malformed error!'
            return
        print "Received error:", util.get_error_message(message[7])
        conn.close()
        return

    # Process a received payload packet
    def process_payload(self, message, conn):
        print "Received Payload"
        if len(message) < 12:
            return '\x03', None
        # Validate some bytes
        message_id = message[0]
        if not util.is_known_message_id(message_id):
            return '\x02', None
        if not message[0] == ord('\x07'):
            return '\x01', None
        if not message[5:7] == self.session_ids[conn]:
            return '\x04', None

        # Get the length of the actual payload and extract it
        length = util.binary_to_int(message[7:11])
        if len(message) < 12 + length:
            return '\x03', None
        payload = message[11:11+length]

        # Validate some bytes
        if not (message[11+length] == ord('\xF0') and message[12+length] == ord('\xF0')) :
            return '\x06', None

        # If no listener, nothing to do
        if self.payload_listener is None:
            return None, None

        # Let listener generate replies
        replies = self.payload_listener.callback(payload, self.user_ids[conn])

        return None, replies

    # Send an error message with a given error code, and close connection
    def send_error(self, conn, error_code):

        error_message = bytearray(10 * '\x00', 'hex')
        error_message[0] = '\x06'
        error_message[1:5] = util.int_to_binary(5,4)
        if self.session_ids.get(conn):
            error_message[5:7] = self.session_ids[conn]
        else:
            error_message[5:7] = '\x00\x00' # session ID not yet generated, can't send it
        error_message[7] = error_code
        error_message[8:10] = '\xF0\xF0'
        print 'Sending error:', util.get_error_message(error_message[7])

        conn.send(error_message)
        conn.close()
        return

    # Create a server_hello message
    def create_hello(self, conn):
        server_hello = bytearray(1249 * '\x00', 'hex')
        server_hello[0] = '\x02'
        server_hello[1:5] = util.int_to_binary(1244, 4)
        server_hello[5] = '\x64'
        server_hello[6] = '\x65'

        # Generate random bytes for server_random
        server_random = ''
        for i in range(7,39):
            server_random += chr(random.randint(0,255))

        server_hello[7:39] = util.text_to_binary(server_random)
        self.server_randoms[conn] = server_random

        # Get next sessionID
        server_id = util.int_to_binary(self.max_server_id, 2)
        self.max_server_id += 1
        self.max_server_id %= 65535
        server_hello[39:41] = server_id
        self.session_ids[conn] = server_hello[39:41]

        server_hello[41:43] = '\x00\x2F'
        server_hello[43] = '\x01'
        server_hello[44:1247] = self.cert
        server_hello[1247:1249] = '\xF0\xF0'

        return server_hello

    # Create a server_finished
    def create_finished(self, conn):
        # First 5 bytes not encrypted
        server_finished = bytearray(5 * '\x00', 'hex')
        server_finished[0] = '\x05'

        # Do encrypt the rest
        server_finished_to_encrypt = bytearray(5 * '\x00', 'hex')
        server_finished_to_encrypt[0:2] = self.session_ids[conn]
        server_finished_to_encrypt[2] = '\x00'
        server_finished_to_encrypt[3:5] = '\xF0\xF0'
        server_finished_encrypted_part = util.encrypt_message(server_finished_to_encrypt, self.master_secrets[conn])

        # Get length of encrypted part, send concatenation of the two parts
        server_finished[1:5] = util.int_to_binary(len(server_finished_encrypted_part), 4)
        server_finished.extend(server_finished_encrypted_part)
        return server_finished

    # Create a payload packet
    def create_payload(self, payload, conn):
        length = len(payload)  # Unencrypted length

        if length > 4294967200:
            print "payload too big todo"
            return

        # First 5 bytes not encrypted
        server_message = bytearray(5 * '\x00', 'hex')
        server_message[0] = '\x07'

        # Do encrypt the rest
        server_message_to_encrypt = bytearray((8+length) * '\x00', 'hex')
        server_message_to_encrypt[0:2] = self.session_ids[conn]
        server_message_to_encrypt[2:6] = util.int_to_binary(length, 4)
        server_message_to_encrypt[6:6+length] = payload
        server_message_to_encrypt[6+length:6+length+2] = '\xF0\xF0'
        server_message_encrypted = util.encrypt_message(server_message_to_encrypt, self.master_secrets[conn])

        # Get length of encrypted part, send concatenation of the two parts
        server_message[1:5] = util.int_to_binary(len(server_message_encrypted), 4)

        return server_message + server_message_encrypted

    # Set the listener to be called on receiving payload
    def set_payload_listener(self, listener):
        self.payload_listener = listener

# For testing purposes
if __name__ == '__main__':
    server = Server('server-04.pem', 'server_prvkey.key')
    server.add_account('project-client', 'Konklave123')
    server.start()
