"""
RSA functions
"""


"""
Encrypt message m (decimal representation) using RSA with key (e,n)
"""
def encrypt_rsa(m, e, n):
    return pow(m,e,n)



"""
Decrypt message c to decimal representation using RSA with key (d,n)
"""
def decrypt_rsa(c, d, n):
    return pow(c,d,n)

# Note that while the above functions seem to imply encryption needs the private key and decryption the public key,
# they can also be used the other way around. In fact they can be used interchangeably
# as they are equal except for variable names.

"""
Converts a string to its decimal representation
by concatenating hexadecimal representations of their ASCII values and converting the result to decimal
"""
def text_to_decimal(m_text):
    m_hex = m_text.encode('hex')
    m_dec = int(m_hex,16)
    return m_dec

"""
Converts a long decimal representation of a string to the plaintext string.
Opposite process of the previous function
"""
def long_to_text(m_long, length):
    # Cast the hex representation to string: easier to slice off unwanted parts
    m_hex = str(hex(m_long))
    # Slice the first two characters (0x) and the final character ('L' for long)
    m_hex = m_hex[2:len(m_hex) - 1]
    # Add leading 0s to reach target length
    m_hex = ((length*2 - len(m_hex)) * "0") + m_hex
    m_text = m_hex.decode('hex')
    return m_text

