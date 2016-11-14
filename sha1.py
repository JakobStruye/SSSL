import textwrap

"""
Converts a string to its binary representation
by concatenating hexadecimal representations of their ASCII values and converting the result to binary
"""
def textToBinary(mText):
    #First to hex
    mHex = mText.encode('hex')
    #Split up in pairs: 2 hexadecimal digits are one character
    chars = textwrap.wrap(mHex, 2)
    result = ""
    #Convert each char to binary, padded to length 8 with leading 0s
    for ch in chars:
        result += bin(int(ch,16))[2:].zfill(8)
    return result


"""
Print hexadecimal representation of integer without extra characters (0x, L)
"""
def printHexSHA1(a):
    aStr = hex(a)
    hexHash = aStr[2:len(aStr)-1].zfill(40)
    assert len(hexHash) == 40
    print hexHash


def digestToString(a):
    aStr = hex(a)
    hexHash = aStr[2:len(aStr)-1].zfill(40)
    assert len(hexHash) == 40
    return hexHash


"""
Helper function to get correct k in SHA1 depending on iteration
"""
def getK(t):
    if t < 20:
        return int("5A827999",16)
    elif t < 40:
        return int("6ED9EBA1",16)
    elif t < 60:
        return int("8F1BBCDC",16)
    else:
        return int("CA62C1D6",16)


"""
Helper function to get right h5 in SHA1 depending on iteration
"""
def getH5(h, t):
    if t < 20:
        return (h[1] & h[2]) | (~h[1] & h[3])
    elif t < 40:
        return h[1]^ h[2] ^ h[3]
    elif t < 60:
        return (h[1] & h[2]) | (h[1] & h[3]) | (h[2] & h[3])
    else:
        return h[1]^ h[2] ^ h[3]


"""
Helper function performing left rotation of n positions on a string
"""
def leftRotate(a,n):
    #bitwise OR of left-shifted and right-shifted a
    #are equal to rotation (shift pads with 0s)
    aLeft = a << n
    aRight = a >> (32-n)
    aRotate = (aLeft ^ aRight) % (2**32)
    return aRotate


"""
Helper function adding padding to binary representation of input string.
Padded result is returned as string of binary form
"""
def pad(a):
    #Get binary representation of string length padded to 64b
    l = len(a)
    lBin = bin(l)[2:].zfill(64)

    #Get the length without the padding's 0s modulo 512
    lNoPadMod = (l + 1 + 64) % 512
    #Add 0s to get length to multiple of 512
    padSize = 512 - lNoPadMod
    padded = a + "1" + (padSize*"0") + lBin
    assert len(padded) % 512 == 0
    return padded


"""
Main part of the SHA1 algorithm, starting from the padded input
"""
def sha1Internal(padA, hList):


    #Note that all asserts here are simply sanity checks

    #These hs will be updated once per chunk
    hOrig = list(hList)

    #Split input into parts of 512b
    chunks = textwrap.wrap(padA,512)
    for chunk in chunks:
        assert len(chunk) == 512
        #Copy the current hs
        h = list(hOrig)
        #Split chunk into parts of 32b
        words = textwrap.wrap(chunk, 32)
        #Words are currently in string form as that's easier to split up
        #Up next are calculations, so first convert to integers
        for i in range(16):
            words[i] = int(words[i],2) % (2**32)

        assert len(words) == 16
        for i in range(16,80):
            #Calculate the following words
            words.append((words[i-3] ^ words[i-8]) ^ (words[i-14] ^ words[i-16]))
            words[i] = leftRotate(words[i],1)
            assert words[i] < (2**32)

        for j in range(80):
            #Main loop: calculate new h values
            k = getK(j)
            h[5] = getH5(h,j)
            temp = (leftRotate(h[0],5) + h[5] + h[4] + k + words[j]) % (2**32)
            h[4] = h[3]
            h[3] = h[2]
            h[2] = leftRotate(h[1],30)
            h[1] = h[0]
            h[0] = temp
            for i in range(len(h)):
                assert h[i] < (2**32)
        #After the main loop, update the original h values
        for i in range(5):
            hOrig[i] = (h[i] + hOrig[i]) % (2**32)
            assert hOrig[i] < (2**32)

    #Concatenate all final h values (implemented through shifts)
    result =  (hOrig[0] << 128) | (hOrig[1] << 96) | (hOrig[2] << 64) | (hOrig[3] << 32) | (hOrig[4])
    assert result < (2**160)
    return result


"""
Full sha1 algorithm starting from string
"""
def sha1(a):

    aBin = textToBinary(a)

    padA = pad(aBin)

    hList = [int("67452301",16), int("EFCDAB89",16), int("98BADCFE",16), int("10325476",16), int("C3D2E1F0",16), 0]

    return sha1Internal(padA, hList)
        



if __name__ == '__main__':
    #Get the hash for both the given string and a slightly modified one
    text = 'Go placidly amid the noise and the haste, and remember what peace there may be in silence'
    print "Hash for original string:"
    hash1 = sha1(text)
    printHexSHA1(hash1)

    text = 'Go placidly amid the noise and the haste, and remember what peace there may be in silencd'
    print "Hash for modified string:"
    hash2 = sha1(text)
    printHexSHA1(hash2)
    difference = bin(hash1 ^ hash2)[2:]
    diffCount = 0
    totalCount = 0
    for b in difference:
        totalCount += 1
        if b == '1':
            diffCount += 1
    print diffCount, "of", totalCount, "bits differ between the two hashes above"

