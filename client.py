import random
import util
import rsa
import sha1
import socket

class Client:

    status = 0
    server_random = -1
    session_id = -1
    client_socket = None
    client_random = ''
    certificate_required = None
    master_secret = None
    private_key = 15250199709679511075706852520218931920862586226950139938104500301373684948285528219578200125958795897780598922907027278290745917408384054580719454188842965572780727027101652369568717990401197110646024638603131783118232131092639581621182826911051011196270811088775862262795741611700499696997167352459934513622150108181418095826050696705549363779862358358393233189560520163106785535319492545898745183439109804783640231042277204269421962449461179792699246562139627266266067745221262954896564470537104834281630506800118219502588256417336585707762540909960941277936950557159506459454566798472128560135656506235741389170953
    n = 24837901994912053415060016243385475317417712009633224511631865509856785468222089587874860251372091919601558478355770440054191585009400476777668701239449326144867678301527398577112380301123866275016986424616254073665339078392065415659123211990097917959442335702306311914233567385024867631951672675219730316838578210434343067511636079081818744400113533624136339709745782321618533725900903084941132241555654812980180563388220808051884801391506840635505073310621874127072108865489246988967830314936790373122088161029787856707927049345768779125257912445784686277424030038539380288863347855630618237433032833865316901740219

    def __init__(self):
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
                print 'connection setup'

    def process_hello(self, message, conn):

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
        self.certificate_required = message[37] == ord('\x01')
        #todo certificate required
        if not (message[1243] == ord('\xF0') and message[1244] == ord('\xF0')) :
            return '\x06' #todo reset conn
        return None

    def process_finished(self, message, conn):

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
        # todo replace with actual server pub key
        pre_master_encrypt = rsa.encrypt_rsa(rsa.text_to_decimal(pre_master), self.private_key, self.n)
        key_length = util.get_length_in_bytes(pre_master_encrypt)

        # Actual message generation
        client_key_exchange = bytearray((1230 + key_length)  * '\x00', 'hex')
        client_key_exchange[0] = '\x03'
        client_key_exchange[1:3] = self.session_id
        # todo certificate
        client_key_exchange[1206:1208] = util.int_to_binary(key_length, 2)
        client_key_exchange[1208:1208+key_length] = util.int_to_binary(pre_master_encrypt, key_length)
        client_key_exchange[1208+key_length:1228+key_length] = util.int_to_binary(sha1.sha1('password'), 20)
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
        self.client_socket.send(client.create_hello())
        client.status = 2
        client.process(self.client_socket)

client = Client()
client.connect('localhost', 8970)
