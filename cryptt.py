import base64

from Crypto import Random
from Crypto.Cipher import AES

import os, random, struct
import StringIO
from Crypto.Cipher import DES

import string
import sys

#AES
def pad(s):
    BS = 16
    return s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
def unpad (s): 
    return s[0:-ord(s[-1])]

def AESencrypt(raw, key):
    raw = pad(raw)
    iv = Random.new().read( AES.block_size )
    cipher = AES.new(key, AES.MODE_CBC, iv )
    return base64.b64encode( iv + cipher.encrypt( raw ) )

def AESdecrypt(enc, key ):
    enc = base64.b64decode(enc)
    iv = enc[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv )
    return unpad(cipher.decrypt( enc[16:] ))

#DES
def DESencrypt(key, msg, chunksize=64):
    iv = ''.join(chr(random.randint(0, 0xFF)) for i in range(8))
    encryptor = DES.new(key, DES.MODE_CFB, iv)

    encryptedMsg = ''
    encryptedMsg += iv
    msg = StringIO.StringIO(msg)

    while True:
        chunk = msg.read(chunksize)
        if len(chunk) == 0:
            break
        elif len(chunk) % 16 != 0:
            chunk += ' ' * (16 - len(chunk) % 16)

        chunk = encryptor.encrypt(chunk)
        encryptedMsg += chunk
    return base64.b64encode( encryptedMsg )

def DESdecrypt(key, enc, chunksize=24):
    enc = StringIO.StringIO(enc)
    iv = enc.read(8)
    decryptor = DES.new(key, DES.MODE_CFB, iv)

    decryptedMsg = ''

    enc = base64.b64decode( str(enc) )
    while True:
        chunk = StringIO.StringIO(enc.read(chunksize))
        if len(chunk) == 0:
            break

        
        decryptedMsg += decryptor.decrypt(chunk)

    return decryptedMsg

#Ceasar
def Cencrypt(letter, key):
    if not letter.isalpha() or len(letter) != 1:
        return letter
    letter = letter.lower()
    value = ord(letter) - 97
    value = (value + key) % 26
    return chr(value + 97)


def Cdecrypt(letter, key):
    if not letter.isalpha() or len(letter) != 1:
        return letter
    letter = letter.lower()
    value = ord(letter) - 97
    value = (value - key) % 26
    return chr(value + 97)

def CEASARencrypt(plaintext, key):
    ciphertext = ''
    for letter in plaintext:
        ciphertext += Cencrypt(letter, key)
    return ciphertext

def CEASARdecrypt(encrypted, key):
    plaintext = ''
    for letter in encrypted:
        plaintext += Cdecrypt(letter, key)
    return plaintext


#Transposition
def insert_dash(string, index):
    temp = string
    return temp[:index] + ' ' + temp[index:]

def findOccurences(s, ch):
    return [i for i, letter in enumerate(s) if letter == ch]

def TRANencrypt(msg, key):
    '''
	Ciphers message using key.
		- key cannot contain repeating characters
	'''
    # ignore all the spaces
    listResult = findOccurences(msg, ' ')
    msg = msg.replace(' ', '')
    # if there are blank boxes in matrix, fill them with random characters
    # so that it can be evenly divided by the key length
    while len(msg) % len(key) != 0:
        msg += random.choice(string.uppercase)
    # spilit the message periodically by a lenght of key and store them
    chunks = [msg[i:i + len(key)] for i in xrange(0, len(msg), len(key))]
    # if you don't understand, uncomment the next line for help
    # print chunks
    # calculate the order we need to apply to it, sorted by ASCII acrrodingly
    order = [''.join(sorted(key)).find(x) for x in key]
    # print order
    # using x to temperarally store the result row by row
    # retrive character one by one according to order
    x = map(lambda k: [c for (y, c) in sorted(zip(order, k))], chunks)
    # print x
    # retrive the result one character by one
    result = [l[i] for i in range(len(key)) for l in x]
    result = ''.join(result)

    for items in listResult:
        result = insert_dash(result, items)

    return result


def TRANdecrypt(msg, key):
    '''
	Deciphers message using key.
		- decrypted message may be suffixed by meaningless characters
	'''
    listResult = findOccurences(msg, ' ')
    msg = msg.replace(' ', '')

    # calculate the order we need to apply to it, sorted by ASCII acrrodingly
    order = [key.find(x) for x in sorted(key)]
    # analyze the string so that we can reverse the result to x in encryption
    chunks = [msg[k + x * len(msg) / len(key)] for k in range(len(msg) / len(key)) for x in range(len(key))]
    # print chunks
    # removing all the symbols
    chunks = ''.join(chunks)
    # print chunks
    # retrive how each row was picked
    chunks = [chunks[i:i + len(key)] for i in xrange(0, len(chunks), len(key))]
    # print chunks
    x = map(lambda k: ''.join([c for (y, c) in sorted(zip(order, k))]), chunks)
    result = ''.join(x)

    for items in listResult:
        result = insert_dash(result, items)

    return result

def encrypt(mess, key, alg):
    result=''
    if(alg==0):
        result = AESencrypt(mess, key)
    elif(alg==1):
        result = DESencrypt(key, mess)
    elif(alg==2):
        key = int(key)
        result = CEASARencrypt(mess, key)
    elif(alg==3):
        result = TRANencrypt(mess, key)
    
    return result

def decrypt(mess, key, alg):
    result=''
    if(alg==0):
        result = AESdecrypt(mess, key)
    elif(alg==1):
        result = DESdecrypt(key, mess)
    elif(alg==2):
        key = int(key)
        result = CEASARdecrypt(mess, key)
    elif(alg==3):
        result = TRANdecrypt(mess, key)

    return result
