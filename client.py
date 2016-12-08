import random
import util
import rsa
import sha1
import socket
import threading
from OpenSSL import crypto
import Crypto.PublicKey.RSA
import M2Crypto
import sys


class Client:

    def __init__(self, certificate, user_id, password):

        self.cert = 0
        self.status = 0
        self.server_random = -1
        self.session_id = -1
        self.server_pubkey = 0
        self.client_socket = None
        self.client_random = ''
        self.certificate_required = None
        self.master_secret = None
        self.connection = None
        self.userID = user_id
        self.password = password
        self.payload_listener = None
        self.buffer = bytearray()

        # Read certificate from file, chop off final newline
        with open(certificate, 'rt') as f:
            self.cert = util.text_to_binary(f.read())
            self.cert = self.cert[0:len(self.cert)-1]
        return

    # Start listening for, processing and replying to connection setup messages
    def process(self, conn):
        print 'Setting up connection...'
        while True:

            buf = conn.recv(8)
            if not buf:
                break
            bytes_buf = bytearray(buf)

            self.buffer.extend(bytes_buf)
            if len(self.buffer) < 5:
                continue # Don't have length yet, can't do anything
            next_length = util.binary_to_int(self.buffer[1:5])

            if len(self.buffer) < next_length + 5:
                continue # Don't have full packet yet, can't do anything

            packet = self.buffer[:next_length+5]

            if packet[0] == ord('\x06'):
                error = self.process_error_setup(packet, conn)
                return error
            if self.status == 2:
                error = self.process_hello(packet, conn)
                if error:
                    self.send_error(conn, error)
                    return error
                conn.send(self.create_key_exchange())
                conn.send(self.create_finished())
                self.status = 5
                self.buffer = self.buffer[next_length+5:]
            elif self.status == 5:
                decrypt_buf = util.decrypt_message(packet[5:next_length+5], self.master_secret)

                error = self.process_finished(packet[0:5] + decrypt_buf, conn)
                if error:
                    self.send_error(conn, error)
                    return error
                self.status = -1
                self.buffer = self.buffer[next_length+5:]
                print 'Connection setup'
                self.connection = conn
                listen_thread = threading.Thread(target=self.listen_payloads, args=(conn,))
                listen_thread.start()
                return 0 # success

    # Start listening for, processing and replying to payload messages
    def listen_payloads(self, conn):
        while True:
            buf = conn.recv(4096)
            if not buf :
                break
            bytes_buf = bytearray(buf)

            self.buffer.extend(bytes_buf)
            if len(self.buffer) > 5:
                continue # Don't have length yet, can't do anything
            next_length = util.binary_to_int(self.buffer[1:5])

            if len(self.buffer) < next_length + 5:
                continue # Don't have full packet yet, can't do anything

            packet = self.buffer[0:5] + util.decrypt_message(self.buffer[5:next_length+5], self.master_secret)

            if packet[0] == ord('\x06'):
                self.process_error_setup(packet, conn)
                return error

            elif self.status == -1: # receiving payloads
                error, reply = self.process_payload(packet, conn)
                if error:
                    self.send_error(conn, error)
                    return

                if reply:
                    print reply
                    conn.send(self.create_payload(reply, conn))


    def process_hello(self, message, conn):
        print "Received Server Hello"
        if len(message) < 1249:
            print 'todo err'
            return
        message_id = message[0]
        if not util.is_known_message_id(message_id):
            return '\x02'
        if not message[0] == ord('\x02'):
            return '\x01'
        if not message[5] == ord('\x64'):
            return '\x05'
        if not message[6] == ord('\x65'):
            return '\x05'
        self.server_random = util.binary_to_text(message[7:39])
        self.session_id = message[39:41]
        if not (message[41] == ord('\x00') and message[42] == ord('\x2F')) :
            return '\x05'
        self.certificate_required = message[43] == ord('\x01')
        server_cert = crypto.load_certificate(crypto.FILETYPE_PEM, util.binary_to_text(message[44:1247]))
        if server_cert.get_issuer().commonName != 'orion' or server_cert.has_expired() :
            return '\x07'
        self.server_pubkey = Crypto.PublicKey.RSA.importKey(M2Crypto.X509.load_cert_string(message[44:1247]).get_pubkey().as_der())
        if not (message[1247] == ord('\xF0') and message[1248] == ord('\xF0')) :
            return '\x06' #todo reset conn
        return None

    def process_finished(self, message, conn):
        print "Received FinishedServer"
        if len(message) < 10:
            print 'todo err'
            return
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

    def process_error_setup(self, message, conn):
        if len(message) < 10:
            print 'Malformed error!'
            return
        print "Received error:", util.get_error_message(message[7])
        conn.close()
        return message[7]

    def process_payload(self, message, conn):
        print "Received Payload"
        if len(message) < 11:
            print 'todo err'
        message_id = message[0]
        if not util.is_known_message_id(message_id):
            return '\x02', None
        if not message[0] == ord('\x07'):
            return '\x01', None
        if not message[5:7] == self.session_id:
            return '\x04', None
    
        length = util.binary_to_int(message[7:9])

        """if len(message) < 7 + length:
            print 'todo err'"""
        payload = message[9:9+length]

        if self.payload_listener is None:
            return None, None

        reply = self.payload_listener.callback_client(payload, self)
        if not (message[9+length] == ord('\xF0') and message[10+length] == ord('\xF0')) :
            return '\x06', None #todo reset conn
        return None, reply


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

    def create_hello(self):
        client_hello = bytearray(43 * '\x00', 'hex')
        client_hello[0] = '\x01'
        client_hello[1:5] = util.int_to_binary(38,4)
        client_hello[5] = '\x64'
        client_hello[6] = '\x65'
        for i in range(7,39):
            self.client_random += chr(random.randint(0,255))

        client_hello[7:39] = util.text_to_binary(self.client_random)
        client_hello[39:41] = '\x00\x2F'
        client_hello[41:43] = '\xF0\xF0'
        return client_hello

    def create_key_exchange(self):
        # First generate pre_master
        pre_master = ""
        for _ in range(48):
            pre_master += chr(random.randint(0,127))
        pre_master_encrypt = rsa.encrypt_rsa(rsa.text_to_decimal(pre_master), self.server_pubkey.e, self.server_pubkey.n)
        key_length = util.get_length_in_bytes(pre_master_encrypt)

        # Actual message generation
        client_key_exchange = bytearray((1234 + key_length)  * '\x00', 'hex')
        client_key_exchange[0] = '\x03'
        client_key_exchange[1:5] = util.int_to_binary(1229+key_length, 4)
        client_key_exchange[5:7] = self.session_id
        client_key_exchange[7:1210] = self.cert
        client_key_exchange[1210:1212] = util.int_to_binary(key_length, 2)
        client_key_exchange[1212:1212+key_length] = util.int_to_binary(pre_master_encrypt, key_length)
        client_key_exchange[1212+key_length:1232+key_length] = util.int_to_binary(sha1.sha1(self.userID + self.password), 20)
        client_key_exchange[1232+key_length:1234+key_length] = '\xF0\xF0'

        self.master_secret = \
            sha1.sha1(
            sha1.digestToString(sha1.sha1(pre_master + sha1.digestToString(sha1.sha1('A' + pre_master + self.client_random + self.server_random))))\
            + sha1.digestToString(sha1.sha1(pre_master + sha1.digestToString(sha1.sha1('BB' + pre_master + self.client_random + self.server_random))))\
            + sha1.digestToString(sha1.sha1(pre_master + sha1.digestToString(sha1.sha1('CCC' + pre_master + self.client_random + self.server_random)))))

        return client_key_exchange

    def create_finished(self):

        client_finished = bytearray((10) * '\x00', 'hex')
        client_finished[0] = '\x04'
        client_finished[1:5] = util.int_to_binary(5, 4)
        client_finished[5:7] = self.session_id
        client_finished[7] = '\x00'
        client_finished[8:10] = '\xF0\xF0'

        return client_finished

    def connect(self, host, port):
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect((host, port))
        self.client_socket.send(self.create_hello())
        self.status = 2
        return self.process(self.client_socket)

    def disconnect(self):
        if self.connection is not None:
            self.connection.close()

    def send_payload(self, payload):

        length = len(payload)
        if length > 16777000:
            print "payload too big todo"
            return
        client_message = bytearray(5 * '\x00', 'hex')
        client_message[0] = '\x07'

        client_message_to_encrypt = bytearray((6 + length) * '\x00', 'hex')
        client_message_to_encrypt[0:2] = self.session_id
        client_message_to_encrypt[2:4] = util.int_to_binary(length, 2)
        client_message_to_encrypt[4:4 + length] = payload
        client_message_to_encrypt[4 + length:4 + length + 2] = '\xF0\xF0'

        client_message_encrypted = util.encrypt_message(client_message_to_encrypt, self.master_secret)

        client_message[1:5] = util.int_to_binary(len(client_message_encrypted), 4)
        print "SENT PAYLOAD"
        self.connection.send(client_message + client_message_encrypted)


    def add_payload_listener(self, listener):
        self.payload_listener = listener

if __name__ == '__main__':
    client = Client('client-05.pem', 'project-client', 'Konklave123')
    error_connect = client.connect('localhost', 8970)
    print error_connect, "ERROR"
    if error_connect == 0:
        client.send_payload('\x01\x02')


