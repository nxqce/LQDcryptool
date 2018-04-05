import base64

from Crypto import Random
from Crypto.Cipher import AES

import os, random, struct
import StringIO
from Crypto.Cipher import DES

#AES
BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
unpad = lambda s : s[0:-ord(s[-1])]

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

        encryptedMsg += encryptor.encrypt(chunk)
    return encryptedMsg

def DESdecrypt(key, enc, chunksize=24):
    enc = StringIO.StringIO(enc)
    iv = enc.read(8)
    decryptor = DES.new(key, DES.MODE_CFB, iv)

    decryptedMsg = ''

    while True:
        chunk = enc.read(chunksize)
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
