"""
RSA functions
"""



"""
Encrypt message m (decimal representation) using public key (e,n),
then decrypt it again using private key (d,n).
Prints the input text and the resulting texts after encrypting and decrypting.
Verifies that decypted text and input text are equal.
"""
def encrypt_decrypt_rsa(m, e, d, n):
    c = encrypt_rsa(m, e, n)
    decrypted_m = decrypt_rsa(c, d, n)
    # Verify successful encryption and decryption. Must not fail given valid keys.
    assert m == decrypted_m
    # Print results
    print "Original message:", m
    print "Encrypted message:", c
    print "Decrypted message:", decrypted_m



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
def long_to_text(m_long):
    # Cast the hex representation to string: easier to slice off unwanted parts
    m_hex = str(hex(m_long))
    # Slice the first two characters (0x) and the final character ('L' for long)
    m_hex = m_hex[2:len(m_hex) - 1]
    # Safety check: hexadecimal value is converted to plain string per two hexadecimal digits:
    # slice the final digit in case of odd number of them
    if len(m_hex) % 2 == 1:
        m_hex = m_hex[:len(m_hex)-1]
    m_text = m_hex.decode('hex')
    return m_text

if __name__ == '__main__':
    # Part 1: Simply encrypt then decrypt using the given values
    encrypt_decrypt_rsa(15, 7, 3, 33)


    print ""
     # Part 2: Decrypt given plaintext using given values and print the result
    m = decrypt_rsa(18721616352027860610532011244613700440823136983474134105356368227777434991605882218996415871539040273826289952593106238953496209104749822344117450601254708536373034264130933521987327974000255146756518397668069770185737907343422454676477169144712992560738066894543224559303296179944700852861503983647039123452966586430244465300085880875741576217308257244398694008512158409779167674407062518499319865294600391474639080900863039538267510568825732583473943114017472152320746478960753673137088195122814398113528864856141781844996825072118049310750120432758298994758267170231934908068721013345590521202959891172540575563129,
                    15250199709679511075706852520218931920862586226950139938104500301373684948285528219578200125958795897780598922907027278290745917408384054580719454188842965572780727027101652369568717990401197110646024638603131783118232131092639581621182826911051011196270811088775862262795741611700499696997167352459934513622150108181418095826050696705549363779862358358393233189560520163106785535319492545898745183439109804783640231042277204269421962449461179792699246562139627266266067745221262954896564470537104834281630506800118219502588256417336585707762540909960941277936950557159506459454566798472128560135656506235741389170953, 24837901994912053415060016243385475317417712009633224511631865509856785468222089587874860251372091919601558478355770440054191585009400476777668701239449326144867678301527398577112380301123866275016986424616254073665339078392065415659123211990097917959442335702306311914233567385024867631951672675219730316838578210434343067511636079081818744400113533624136339709745782321618533725900903084941132241555654812980180563388220808051884801391506840635505073310621874127072108865489246988967830314936790373122088161029787856707927049345768779125257912445784686277424030038539380288863347855630618237433032833865316901740219)
    print "Decrypted message:", long_to_text(m)

