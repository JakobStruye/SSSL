from __future__ import division
import math
from Crypto.Cipher import AES
import sha1
import base64

message_ids = [ord('\x01'), ord('\x02'), ord('\x03'), ord('\x04'), ord('\x05'), ord('\x06'), ord('\x07')]

error_codes = {ord('\x01') : 'Unexpected message type',
               ord('\x02') : "Unknown message type",
               ord('\x03') : "Length error",
               ord('\x04') : "Bad Session ID",
               ord('\x05') : "Unsupported field",
               ord('\x06') : "Unsupported structure",
               ord('\x07') : "Incorrect server certificate",
               ord('\x08') : "Incorrect client certificate",
               ord('\x09') : "Incorrect login",
               ord('\x0A') : "Bad Encryption",
               ord('\x0B') : "Unknown error"}

def int_to_binary(a, length):
    if length < 1:
        return None
    a_bytes = bytearray(length * '\x00', 'hex')# length * [None]
    i = length
    while i > 0:
        i -= 1
        a_bytes[i] = int(a & 0xFF)
        a >>= 8
    return a_bytes


def binary_to_int(bytes):
    result = 0
    for i in range(len(bytes)):
        result <<= 8
        result += bytes[i]
    return result


def binary_to_long(bytes):
    result = 0L
    for i in range(len(bytes)):
        result <<= 8
        result += bytes[i]
    return result

def hex_to_binary(a, length):
    if length < 1:
        return None
    a_bytes = length * [None]
    i = length
    while i > 0:
        i -= 1
        a_bytes[i] = a & 0xFF
        a >>= 2
    return a_bytes

def binary_to_text(bytes):
    result = ''
    for i in range(len(bytes)):
        result += chr(bytes[i])
    return result

def text_to_binary(a):
    length = len(a)
    if length < 1:
        return None
    a_bytes = bytearray(length * '\x00', 'hex')# length * [None]
    for i in range(length):
        a_bytes[i] = ord(a[i])
    return a_bytes

def is_known_message_id(id):
    return id in message_ids

def get_length_in_bytes(value):
    if value < 1:
        return 1
    length = 0
    while value > 0:
        value >>= 1
        length += 1
    return int(math.ceil(length / 8))


def pad_for_aes(array):
    return bytes(array + (16 - len(array))%16 * '\x00')

def encrypt_message(array, master_secret):
    aes = AES.new(sha1.digestToString(master_secret)[:16], AES.MODE_CBC, 16 * '\00')
    return base64.b64encode(aes.encrypt(bytes(array + (16 - len(array))%16 * '\x00')))


def decrypt_message(bytes, master_secret):
    aes = AES.new(sha1.digestToString(master_secret)[:16], AES.MODE_CBC, 16 * '\00')
    return bytearray(aes.decrypt(base64.b64decode(bytes)))

def get_error_message(error_code) :
    if error_code in error_codes:
        return error_codes[error_code]
    return 'Unknown error'


