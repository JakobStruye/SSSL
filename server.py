import random
import util
import socket
import threading
import sha1
import rsa
from OpenSSL import crypto
import Crypto.PublicKey.RSA
import M2Crypto
import sys

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
        self.buffers = dict()
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
        self.buffers[conn] = bytearray()
        print 'Setting up new connection...'
        while True:
            buf = conn.recv(8)
            print "RECEIVED"
            if not buf:
                break
            bytes_buf = bytearray(buf)
            self.buffers[conn].extend(bytes_buf)
            if len(self.buffers[conn]) < 5:
                continue # Don't have length yet, can't do anything
            next_length = util.binary_to_int(self.buffers[conn][1:5])

            if len(self.buffers[conn]) < next_length + 5:
                print "2SHORT", len(self.buffers[conn]), next_length
                continue # Don't have full packet yet, can't do anything

            packet = self.buffers[conn][:next_length+5]

            if packet[0] == ord('\x06'):
                self.process_error_setup(packet, conn)

            elif self.statuses[conn] == 1:
                error = self.process_hello(packet, conn)
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
                    # send reply
                    self.statuses[conn] = 4
            elif self.statuses[conn] == 4:
                error = self.process_finished(packet, conn)
                if error:
                    self.send_error(conn, error)
                    return
                else:
                    # send reply
                    conn.send(self.create_finished(conn))
                    self.statuses[conn] = -1
                    print 'Connection setup'
            elif self.statuses[conn] == -1: # receiving payloads
                decrypted = packet[0:5] + util.decrypt_message(packet[5:next_length+5], self.master_secrets[conn])
                error, replies = self.process_payload(decrypted, conn)
                if error:
                    self.send_error(conn, error)
                    return
                # send reply

                elif replies:
                    for reply in replies:
                        conn.send(self.create_payload(reply, conn))
                        print "SENT REPLY"
                        threading.sleep(0.01)

            self.buffers[conn] = self.buffers[conn][next_length+5:]


    def process_hello(self, message, conn):
        print "Received ClientHello"
        if len(message) < 43:
            print 'todo err'
        message_id = message[0]
        if not util.is_known_message_id(message_id):
            return '\x02'
        if not message[0] == ord('\x01'):
            return '\x01'
        if not message[5] == ord('\x64'):
            return '\x05'
        if not message[6] == ord('\x65'):
            return '\x05'
        self.client_randoms[conn] = util.binary_to_text(message[7:39])
        if not (message[39] == ord('\x00') and message[40] == ord('\x2F')) :
            return '\x05'
        if not (message[41] == ord('\xF0') and message[42] == ord('\xF0')) :
            return '\x06' #todo reset conn
        return None

    def process_key_exchange(self, message, conn):
        print "Received ClientKeyExchange"
        if len(message) < 1234:
            print 'todo err'
        message_id = message[0]
        if not util.is_known_message_id(message_id):
            return '\x02'
        if not message[0] == ord('\x03'):
            return '\x01'
        if not message[5:7] == self.session_ids[conn]:
            return '\x04'
        client_cert = crypto.load_certificate(crypto.FILETYPE_PEM, util.binary_to_text(message[7:1210]))
        if client_cert.get_issuer().commonName != 'orion' or client_cert.has_expired() :
            return '\x07'
        self.client_pubkeys[conn] = Crypto.PublicKey.RSA.importKey(M2Crypto.X509.load_cert_string(message[7:1210]).get_pubkey().as_der())

        length = util.binary_to_int(message[1210:1212])

        pre_master = rsa.long_to_text(rsa.decrypt_rsa(util.binary_to_long(message[1212:1212+length]), self.private_key.d, self.private_key.n), 48)
        user_id = client_cert.get_subject().commonName
        if not message[1212+length:1232+length] == util.int_to_binary(self.accounts[user_id], 20):
            return '\x09'
        self.user_ids[conn] = user_id
        if not (message[1232+length] == ord('\xF0') and message[1233+length] == ord('\xF0')) :
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
        if len(message) < 10:
            print 'todo err'
        message_id = message[0]
        if not util.is_known_message_id(message_id):
            return '\x02'
        if not message[0] == ord('\x04'):
            return '\x01'
        if not message[5:7] == self.session_ids[conn]:
            return '\x04'
        #skip state
        if not (message[8] == ord('\xF0') and message[9] == ord('\xF0')) :
            return '\x06' #todo reset conn
        return None

    def process_error_setup(self, message, conn):
        if len(message) < 10:
            print 'Malformed error!'
            return
        print util.get_error_message(message[7])
        conn.close()
        return


    def process_payload(self, message, conn):
        print "Received Payload"
        if len(message) < 11:
            print 'todo err'
        message_id = message[0]
        if not util.is_known_message_id(message_id):
            return '\x02', None
        if not message[0] == ord('\x07'):
            return '\x01', None
        if not message[5:7] == self.session_ids[conn]:
            return '\x04', None
    
        length = util.binary_to_int(message[7:9])

        if len(message) < 11 + length:
            print 'todo err'
        payload = message[9:9+length]

        if self.payload_listener is None:
            return None, None

        replies = self.payload_listener.callback(payload, self.user_ids[conn])
        if not (message[9+length] == ord('\xF0') and message[10+length] == ord('\xF0')) :
            return '\x06', None #todo reset conn"
        return None, replies



    def send_error(self, conn, error_code):

        error_message = bytearray(10 * '\x00', 'hex')
        error_message[0] = '\x06'
        error_message[1:5] = util.int_to_binary(5,4)
        error_message[5:7] = self.session_ids[conn]
        error_message[7] = error_code
        error_message[8:10] = '\xF0\xF0'
        print 'Sending error:', util.get_error_message(error_message[7])

        conn.send(error_message)
        conn.close()
        return


    def create_hello(self, conn):
        server_hello = bytearray(1249 * '\x00', 'hex')
        server_hello[0] = '\x02'
        server_hello[1:5] = util.int_to_binary(1244, 4)
        server_hello[5] = '\x64'
        server_hello[6] = '\x65'

        server_random = ''
        for i in range(7,39):
            server_random += chr(random.randint(0,255))

        server_hello[7:39] = util.text_to_binary(server_random)
        self.server_randoms[conn] = server_random

        server_id = util.int_to_binary(self.max_server_id, 2)
        self.max_server_id += 1
        server_hello[39:41] = server_id
        self.session_ids[conn] = server_hello[39:41]

        server_hello[41:43] = '\x00\x2F'
        server_hello[43] = '\x01'
        server_hello[44:1247] = self.cert
        server_hello[1247:1249] = '\xF0\xF0'
        print "CREATED HELLO"

        return server_hello

    def create_finished(self, conn):
        server_finished = bytearray((5) * '\x00', 'hex')
        server_finished[0] = '\x04'
        server_finished_to_encrypt = bytearray((5) * '\x00', 'hex')
        server_finished_to_encrypt[0:2] = self.session_ids[conn]
        server_finished_to_encrypt[2] = '\x00'
        server_finished_to_encrypt[3:5] = '\xF0\xF0'
        server_finished_encrypted_part = util.encrypt_message(server_finished_to_encrypt, self.master_secrets[conn])

        server_finished[1:5] = util.int_to_binary(len(server_finished_encrypted_part), 4)
        server_finished.extend(server_finished_encrypted_part)
        print server_finished[0], "FIN"
        return server_finished

    def create_payload(self, payload, conn):
        length = len(payload)
        if length > 16777000:
            print "payload too big todo"
            return
        server_message = bytearray(5 * '\x00', 'hex')
        server_message[0] = '\x07'

        server_message_to_encrypt = bytearray((6+length) * '\x00', 'hex')
        server_message_to_encrypt[0:2] = self.session_ids[conn]
        server_message_to_encrypt[2:4] = util.int_to_binary(length, 2)
        server_message_to_encrypt[4:4+length] = payload
        server_message_to_encrypt[4+length:4+length+2] = '\xF0\xF0'

        server_message_encrypted = util.encrypt_message(server_message_to_encrypt, self.master_secrets[conn])

        server_message[1:5] = util.int_to_binary(len(server_message_encrypted), 4)


        return server_message + server_message_encrypted


    def add_payload_listener(self, listener):
        self.payload_listener = listener


if __name__ == '__main__':
    server = Server('server-04.pem', 'server_prvkey.key')
    server.add_account('project-client', 'Konklave123')
    server.start()
