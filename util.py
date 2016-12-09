from __future__ import division
import math
from Crypto.Cipher import AES
import sha1
import base64

message_ids = [ord('\x01'), ord('\x02'), ord('\x03'), ord('\x04'), ord('\x05'), ord('\x06'), ord('\x07')]

error_codes = {ord('\x01'): 'Unexpected message type',
               ord('\x02'): "Unknown message type",
               ord('\x03'): "Length error",
               ord('\x04'): "Bad Session ID",
               ord('\x05'): "Unsupported field",
               ord('\x06'): "Unsupported structure",
               ord('\x07'): "Incorrect server certificate",
               ord('\x08'): "Incorrect client certificate",
               ord('\x09'): "Incorrect login",
               ord('\x0A'): "Bad Encryption",
               ord('\x0B'): "Unknown error"}


# Converts integer to binary, padded to length bytes
def int_to_binary(a, length):
    if length < 1:
        return None
    a_bytes = bytearray(length * '\x00', 'hex')
    i = length
    while i > 0:
        i -= 1
        a_bytes[i] = int(a & 0xFF)
        a >>= 8
    return a_bytes


# Converts bytes to an integer
def binary_to_int(byte_array):
    result = 0
    for i in range(len(byte_array)):
        result <<= 8
        result += byte_array[i]
    return result


# Converts bytes to a long
def binary_to_long(byte_array):
    result = 0L
    for i in range(len(byte_array)):
        result <<= 8
        result += byte_array[i]
    return result


# Converts array of hex values to binary string, padded to length bytes
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


# Converts string representation of hex to binary string, padded to length bytes
def hex_string_to_binary(a, length):
    if length < 1:
        return None
    a_bytes = length * [None]
    i = length
    while i > 0:
        i -= 1
        a_bytes[i] = int(a[2*i:2*i+2], 16) & 0xFF
    return a_bytes


# Converts bytes to string
def binary_to_text(bytes):
    result = ''
    for i in range(len(bytes)):
        result += chr(bytes[i])
    return result


# Converts string to binary representation
def text_to_binary(a):
    length = len(a)
    if length < 1:
        return None
    a_bytes = bytearray(length * '\x00', 'hex')
    for i in range(length):
        a_bytes[i] = ord(a[i])
    return a_bytes


# True if message ID in list of known IDs
def is_known_message_id(message_id):
    return message_id in message_ids


# Gets the minimum number of bytes required to represent integer value (unsigned)
def get_length_in_bytes(value):
    if value < 1:
        return 1
    length = 0
    while value > 0:
        value >>= 1
        length += 1
    return int(math.ceil(length / 8))


# Pads and encrypts a message using a given master secret
def encrypt_message(array, master_secret):
    # create NEW AES object
    aes = AES.new(sha1.digestToString(master_secret)[:16], AES.MODE_CBC, 16 * '\00')
    # Pad the array, encrypt it, and convert it to base64
    return base64.b64encode(aes.encrypt(bytes(array + (16 - len(array)) % 16 * '\x00')))


# Decrypts a message using a given master secret
def decrypt_message(byte_array, master_secret):
    # create NEW AES object
    aes = AES.new(sha1.digestToString(master_secret)[:16], AES.MODE_CBC, 16 * '\00')
    # Decode from base64, decrypt and convert to bytearray
    return bytearray(aes.decrypt(base64.b64decode(byte_array)))


# Gets the string representation of an error code
def get_error_message(error_code) :
    if error_code in error_codes:
        return error_codes[error_code]
    return 'Unknown error'
