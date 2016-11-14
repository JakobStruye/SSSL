import random
import util
import base64
import socket
import threading
import sha1
import rsa

class Server:

    max_server_id = 0
    key_hash = 0
    connections = list()
    statuses = dict()
    client_randoms = dict()
    server_randoms = dict()
    master_secrets = dict()
    session_ids = dict()
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    private_key = 65537
    password = 'password' # todo replace with one password per user


    def __init__(self):
        with open('server-04.pem') as f:
            f.readline() #skip
            key_hash_str = ""
            for _ in range(18):
                key_hash_str += f.readline()
            key_hash_str = key_hash_str.replace('\n', '')
            print key_hash_str
            print base64.b64decode(key_hash_str)
            #self.keyHash = int(base64.b64decode(key_hash_str),16)

            self.server_socket.bind(('0.0.0.0', 8970))
            self.server_socket.listen(1024)  # become a server socket, maximum 1024 connections

            listen_thread = threading.Thread(target=self.listen)
            listen_thread.start()
            listen_thread.join()

        return

    def listen(self):
        while True:
            print 'listenloop'
            conn, address = self.server_socket.accept()
            self.connections.append(conn)
            self.statuses[conn] = 1
            process_thread = threading.Thread(target=self.process, args=(conn,))
            process_thread.start()

    def process(self, conn):
        print 'processing'
        while True:
            buf = conn.recv(99999)
            if not buf :
                break
            bytes_buf = bytearray(buf)
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


    def process_hello(self, message, conn):

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

        if len(message) < 1230:
            print 'todo err'
        message_id = message[0]
        if not util.is_known_message_id(message_id):
            return '\x02'
        if not message[0] == ord('\x03'):
            return '\x01'
        if not message[1:3] == self.session_ids[conn]:
            return '\x04'
        # todo certificate
        length = util.binary_to_int(message[1206:1208])
        print length
        pre_master = rsa.long_to_text(rsa.decrypt_rsa(util.binary_to_long(message[1208:1208+length]), self.private_key, 24837901994912053415060016243385475317417712009633224511631865509856785468222089587874860251372091919601558478355770440054191585009400476777668701239449326144867678301527398577112380301123866275016986424616254073665339078392065415659123211990097917959442335702306311914233567385024867631951672675219730316838578210434343067511636079081818744400113533624136339709745782321618533725900903084941132241555654812980180563388220808051884801391506840635505073310621874127072108865489246988967830314936790373122088161029787856707927049345768779125257912445784686277424030038539380288863347855630618237433032833865316901740219))
        # todo masterkey
        if not message[1208+length:1228+length] == util.int_to_binary(sha1.sha1(self.password), 20):
            return '\x09'
        if not (message[1228+length] == ord('\xF0') and message[1229+length] == ord('\xF0')) :
            return '\x06' #todo reset conn

        server_random = self.server_randoms[conn]
        client_random = self.client_randoms[conn]
        print type(pre_master)
        print type(client_random)
        print type(server_random)
        master_secret = \
            sha1.sha1(pre_master + sha1.digestToString(sha1.sha1('A' + pre_master + client_random + server_random)))\
            + sha1.sha1(pre_master + sha1.digestToString(sha1.sha1('BB' + pre_master + client_random + server_random)))\
            + sha1.sha1(pre_master + sha1.digestToString(sha1.sha1('CCC' + pre_master + client_random + server_random)))
        master_secret %= 2**textfac.
        print master_secret
        print util.get_length_in_bytes(master_secret)
        master_secret >>= 32
        print util.get_length_in_bytes(master_secret)
        self.master_secrets[conn] = master_secret

        return None

    def process_finished(self, message, conn):

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


    def send_error(self, conn, error_code):
        print 'ERROR', ord(error_code)
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
        #server_hello[40:1243] = util.hex_to_binary(self.keyHash, 1203)
        server_hello[1243:1245] = '\xF0\xF0'
        return server_hello


    def create_finished(self, conn):
        server_finished = bytearray((6) * '\x00', 'hex')
        server_finished[0] = '\x04'
        server_finished[1:3] = self.session_ids[conn]
        server_finished[3] = '\x00'
        server_finished[4:6] = '\xF0\xF0'
        return server_finished


server = Server()