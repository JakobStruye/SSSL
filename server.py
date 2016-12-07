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

        self.cert = 0
        self.private_key = 0
        self.max_server_id = 0
        self.key_hash = 0
        self.connections = list()
        self.statuses = dict()
        self.client_randoms = dict()
        self.server_randoms = dict()
        self.client_pubkeys = dict()
        self.master_secrets = dict()
        self.session_ids = dict()
        self.user_ids = dict()
        self.aess = dict()
        self.accounts = dict()
        self.payload_listener = None
        with open(certificate, 'rt') as f:
            self.cert = util.text_to_binary(f.read())
            self.cert = self.cert[0:len(self.cert)-1]

        with open(key, 'rt') as f:
            self.private_key = Crypto.PublicKey.RSA.importKey(f.read())

    def add_account(self, username, password):
        self.accounts[username] = sha1.sha1(username+password)


    def add_account_hashed(self, username, digest):
        self.accounts[username] = digest

    def start(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind(('0.0.0.0', 8970))
        server_socket.listen(1024)  # become a server socket, maximum 1024 connections

        listen_thread = threading.Thread(target=self.listen, args=(server_socket,))
        listen_thread.start()
        #listen_thread.join()

        return

    def listen(self, server_socket):
        while True:
            print 'Listening for new connection...'
            conn, address = server_socket.accept()
            self.connections.append(conn)
            self.statuses[conn] = 1
            process_thread = threading.Thread(target=self.process, args=(conn,))
            process_thread.start()

    def process(self, conn):
        print 'Setting up new connection...'
        while True:
            buf = conn.recv(99999)
            if not buf:
                break
            bytes_buf = bytearray(buf)
            if bytes_buf[0] == ord('\x06'):
                self.process_error_setup(bytes_buf, conn)
                return
            if self.statuses[conn] == 1:
                error = self.process_hello(bytes_buf, conn)
                if error:
                    self.send_error(conn, error)
                    return
                conn.send(self.create_hello(conn))
                self.statuses[conn] = 3
            elif self.statuses[conn] == 3:
                error = self.process_key_exchange(bytes_buf, conn)
                if error:
                    self.send_error(conn, error)
                    return
                # send reply
                self.statuses[conn] = 4
            elif self.statuses[conn] == 4:
                error = self.process_finished(bytes_buf, conn)
                if error:
                    self.send_error(conn, error)
                    return
                # send reply
                conn.send(self.create_finished(conn))
                self.statuses[conn] = -1
                print 'Connection setup'
            elif self.statuses[conn] == -1: #receiving payloads
                error, replies = self.process_payload(util.decrypt_message(bytes_buf, self.master_secrets[conn]), conn)
                if error:
                    self.send_error(conn, error)
                    return
                # send reply

                if replies:
                    for reply in replies:
                        conn.send(self.create_payload(reply, conn))
                        print "SENT REPLY"
                        threading._sleep(0.01)


    def process_hello(self, message, conn):
        print "Received ClientHello"
        if len(message) < 39:
            print 'todo err'
        message_id = message[0]
        if not util.is_known_message_id(message_id):
            return '\x02'
        if not message[0] == ord('\x01'):
            return '\x01'
        if not message[1] == ord('\x64'):
            return '\x05'
        if not message[2] == ord('\x65'):
            return '\x05'
        self.client_randoms[conn] = util.binary_to_text(message[3:35])
        if not (message[35] == ord('\x00') and message[36] == ord('\x2F')) :
            return '\x05'
        if not (message[37] == ord('\xF0') and message[38] == ord('\xF0')) :
            return '\x06' #todo reset conn
        return None

    def process_key_exchange(self, message, conn):
        print "Received ClientKeyExchange"
        if len(message) < 1230:
            print 'todo err'
        message_id = message[0]
        if not util.is_known_message_id(message_id):
            return '\x02'
        if not message[0] == ord('\x03'):
            return '\x01'
        if not message[1:3] == self.session_ids[conn]:
            return '\x04'
        client_cert = crypto.load_certificate(crypto.FILETYPE_PEM, util.binary_to_text(message[3:1206]))
        if client_cert.get_issuer().commonName != 'orion' or client_cert.has_expired() :
            return '\x07'
        self.client_pubkeys[conn] = Crypto.PublicKey.RSA.importKey(M2Crypto.X509.load_cert_string(message[3:1206]).get_pubkey().as_der())

        length = util.binary_to_int(message[1206:1208])

        pre_master = rsa.long_to_text(rsa.decrypt_rsa(util.binary_to_long(message[1208:1208+length]), self.private_key.d, self.private_key.n), 48)
        user_id = client_cert.get_subject().commonName
        if not message[1208+length:1228+length] == util.int_to_binary(self.accounts[user_id], 20):
            return '\x09'
        self.user_ids[conn] = user_id
        if not (message[1228+length] == ord('\xF0') and message[1229+length] == ord('\xF0')) :
            return '\x06' #todo reset conn

        server_random = self.server_randoms[conn]
        client_random = self.client_randoms[conn]

        master_secret = \
            sha1.sha1(
            sha1.digestToString(sha1.sha1(pre_master + sha1.digestToString(sha1.sha1('A' + pre_master + client_random + server_random))))\
            + sha1.digestToString(sha1.sha1(pre_master + sha1.digestToString(sha1.sha1('BB' + pre_master + client_random + server_random))))\
            + sha1.digestToString(sha1.sha1(pre_master + sha1.digestToString(sha1.sha1('CCC' + pre_master + client_random + server_random)))))

        self.master_secrets[conn] = master_secret

        return None

    def process_finished(self, message, conn):
        print "Received FinishedClient"
        if len(message) < 6:
            print 'todo err'
        message_id = message[0]
        if not util.is_known_message_id(message_id):
            return '\x02'
        if not message[0] == ord('\x04'):
            return '\x01'
        if not message[1:3] == self.session_ids[conn]:
            return '\x04'
        #skip state
        if not (message[4] == ord('\xF0') and message[5] == ord('\xF0')) :
            return '\x06' #todo reset conn
        return None

    def process_error_setup(self, message, conn):
        if len(message) < 4:
            print 'Malformed error!'
            return
        print util.get_error_message(message[3])
        conn.close()
        return


    def process_payload(self, message, conn):
        print "Received Payload"
        if len(message) < 7:
            print 'todo err'
        message_id = message[0]
        if not util.is_known_message_id(message_id):
            return '\x02', None
        if not message[0] == ord('\x07'):
            return '\x01', None
        if not message[1:3] == self.session_ids[conn]:
            return '\x04', None
    
        length = util.binary_to_int(message[3:5])

        if len(message) < 7 + length:
            print 'todo err'
        payload = message[5:5+length]

        replies = self.payload_listener.callback(payload, self.user_ids[conn])
        if not (message[5+length] == ord('\xF0') and message[6+length] == ord('\xF0')) :
            return '\x06', None #todo reset conn
        return None, replies



    def send_error(self, conn, error_code):

        error_message = bytearray(6 * '\x00', 'hex')
        error_message[0] = '\x06'
        error_message[1:3] = self.session_ids[conn]
        error_message[3] = error_code
        error_message[4:6] = '\xF0\xF0'
        print 'Sending error:', util.get_error_message(error_message[3])

        conn.send(error_message)
        conn.close()
        return


    def create_hello(self, conn):
        server_hello = bytearray(1245 * '\x00', 'hex')
        server_hello[0] = '\x02'
        server_hello[1] = '\x64'
        server_hello[2] = '\x65'

        server_random = ''
        for i in range(3,35):
            server_random += chr(random.randint(0,255))

        server_hello[3:35] = util.text_to_binary(server_random)
        self.server_randoms[conn] = server_random

        server_id = util.int_to_binary(self.max_server_id, 2)
        self.max_server_id += 1
        server_hello[35:37] = server_id
        self.session_ids[conn] = server_hello[35:37]


        server_hello[37:39] = '\x00\x2F'
        server_hello[39] = '\x01'
        server_hello[40:1243] = self.cert
        server_hello[1243:1245] = '\xF0\xF0'
        return server_hello

    def create_finished(self, conn):
        server_finished = bytearray((6) * '\x00', 'hex')
        server_finished[0] = '\x04'
        server_finished[1:3] = self.session_ids[conn]
        server_finished[3] = '\x00'
        server_finished[4:6] = '\xF0\xF0'

        server_finished_encrypted = util.encrypt_message(server_finished, self.master_secrets[conn])
        return server_finished_encrypted

    def create_payload(self, payload, conn):
        length = len(payload)
        if length > 65536:
            print "payload too big todo"
            return
        server_message = bytearray((7 + length) * '\x00', 'hex')
        server_message[0] = '\x07'
        server_message[1:3] = self.session_ids[conn]
        server_message[3:5] = util.int_to_binary(length, 2)
        server_message[5:5+length] = payload
        server_message[5+length:5+length+2] = '\xF0\xF0'

        server_message_encrypted = util.encrypt_message(server_message, self.master_secrets[conn])

        return server_message_encrypted


    def add_payload_listener(self, listener):
        self.payload_listener = listener


if __name__ == '__main__':
    server = Server('server-04.pem', 'server_prvkey.key')
    server.add_account('project-client', 'Konklave123')
    server.start()
