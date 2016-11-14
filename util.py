from __future__ import division
import math

message_ids = [ord('\x01'), ord('\x02'), ord('\x03'), ord('\x04'), ord('\x05')]

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
    print value
    print 'len', int(math.ceil(length / 8))
    return int(math.ceil(length / 8))