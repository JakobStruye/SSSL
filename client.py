import random
import util
import rsa
import sha1
import socket
from OpenSSL import crypto
import Crypto.PublicKey.RSA
import M2Crypto


class Client:


    cert = 0
    status = 0
    server_random = -1
    session_id = -1
    server_pubkey = 0
    client_socket = None
    client_random = ''
    certificate_required = None
    master_secret = None
    connection = None
    userID = "project-client"
    password = "Konklave-123"

    def __init__(self):
        with open('client-05.pem', 'rt') as f:
            self.cert = util.text_to_binary(f.read())
            self.cert = self.cert[0:len(self.cert)-1]
        return

    def process(self, conn):
        print 'Setting up connection...'
        while True:
            buf = conn.recv(99999)
            if not buf :
                break
            bytes_buf = bytearray(buf)
            if self.status == 2:
                error = self.process_hello(bytes_buf, conn)
                if error:
                    self.send_error(conn, error)
                    return
                conn.send(self.create_key_exchange())
                #send reply
                conn.send(self.create_finished())
                self.status = 5
            elif self.status == 5:
                bytes_buf = util.decrypt_message(bytes_buf, self.master_secret)

                error = self.process_finished(bytes_buf, conn)
                if error:
                    self.send_error(conn, error)
                    return
                self.status = -1
                print 'Connection setup'
                self.connection = conn
                return

    def process_hello(self, message, conn):
        print "Received Server Hello"
        if len(message) < 1245:
            print 'todo err'
            return
        message_id = message[0]
        if not util.is_known_message_id(message_id):
            return '\x02'
        if not message[0] == ord('\x02'):
            return '\x01'
        if not message[1] == ord('\x64'):
            return '\x05'
        if not message[2] == ord('\x65'):
            return '\x05'
        self.server_random = util.binary_to_text(message[3:35])
        self.session_id = message[35:37]
        if not (message[37] == ord('\x00') and message[38] == ord('\x2F')) :
            return '\x05'
        self.certificate_required = message[39] == ord('\x01')
        server_cert = crypto.load_certificate(crypto.FILETYPE_PEM, util.binary_to_text(message[40:1243]))
        if server_cert.get_issuer().commonName != 'orion' or server_cert.has_expired() :
            return '\x07'
        self.server_pubkey = Crypto.PublicKey.RSA.importKey(M2Crypto.X509.load_cert_string(message[40:1243]).get_pubkey().as_der())
        if not (message[1243] == ord('\xF0') and message[1244] == ord('\xF0')) :
            return '\x06' #todo reset conn
        return None

    def process_finished(self, message, conn):
        print "Received FinishedServer"
        if len(message) < 6:
            print 'todo err'
            return
        message_id = message[0]
        if not util.is_known_message_id(message_id):
            return '\x02'
        if not message[0] == ord('\x04'):
            return '\x01'
        if not message[1:3] == self.session_id:
            return '\x04'
        #skip state
        if not (message[4] == ord('\xF0') and message[5] == ord('\xF0')) :
            return '\x06' #todo reset conn
        return None

    def send_error(self, conn, error_code):
        print 'ERROR', ord(error_code)
        return

    def create_hello(self):
        client_hello = bytearray(39 * '\x00', 'hex')
        client_hello[0] = '\x01'
        client_hello[1] = '\x64'
        client_hello[2] = '\x65'
        for i in range(3,35):
            self.client_random += chr(random.randint(0,255))

        client_hello[3:35] = util.text_to_binary(self.client_random)
        client_hello[35:37] = '\x00\x2F'
        client_hello[37:39] = '\xF0\xF0'
        return client_hello

    def create_key_exchange(self):
        # First generate pre_master
        pre_master = ""
        for _ in range(48):
            pre_master += chr(random.randint(0,127))
        pre_master_encrypt = rsa.encrypt_rsa(rsa.text_to_decimal(pre_master), self.server_pubkey.e, self.server_pubkey.n)
        key_length = util.get_length_in_bytes(pre_master_encrypt)

        # Actual message generation
        client_key_exchange = bytearray((1230 + key_length)  * '\x00', 'hex')
        client_key_exchange[0] = '\x03'
        client_key_exchange[1:3] = self.session_id
        client_key_exchange[3:1206] = self.cert
        client_key_exchange[1206:1208] = util.int_to_binary(key_length, 2)
        client_key_exchange[1208:1208+key_length] = util.int_to_binary(pre_master_encrypt, key_length)
        client_key_exchange[1208+key_length:1228+key_length] = util.int_to_binary(sha1.sha1(self.userID + self.password), 20)
        client_key_exchange[1228+key_length:1230+key_length] = '\xF0\xF0'

        self.master_secret = \
            sha1.sha1(
            sha1.digestToString(sha1.sha1(pre_master + sha1.digestToString(sha1.sha1('A' + pre_master + self.client_random + self.server_random))))\
            + sha1.digestToString(sha1.sha1(pre_master + sha1.digestToString(sha1.sha1('BB' + pre_master + self.client_random + self.server_random))))\
            + sha1.digestToString(sha1.sha1(pre_master + sha1.digestToString(sha1.sha1('CCC' + pre_master + self.client_random + self.server_random)))))

        return client_key_exchange

    def create_finished(self):

        client_finished = bytearray((6) * '\x00', 'hex')
        client_finished[0] = '\x04'
        client_finished[1:3] = self.session_id
        client_finished[3] = '\x00'
        client_finished[4:6] = '\xF0\xF0'

        return client_finished

    def connect(self, host, port):
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect((host, port))
        self.client_socket.send(self.create_hello())
        self.status = 2
        self.process(self.client_socket)

    def disconnect(self):
        if self.connection is not None:
            self.connection.close()

if __name__ == '__main__':
    client = Client()
    client.connect('localhost', 8970)
