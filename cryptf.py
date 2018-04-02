import os, random, struct
from Crypto.Hash import MD5
from Crypto.Cipher import AES
from Crypto.Cipher import DES3
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import zlib
import base64

#MD5 File Hash
def MD5_hash(in_filename):
    fi = open(in_filename, 'rb')
    data = fi.read()
    hashObject = MD5.new(data)
    return hashObject.hexdigest()

#AES
def AES_encrypt_file(key, in_filename, out_filename=None, chunksize=64*1024):
    """ Encrypts a file using AES (CBC mode) with the
        given key.

        key:
            The encryption key - a string that must be
            either 16, 24 or 32 bytes long. Longer keys
            are more secure.

        in_filename:
            Name of the input file

        out_filename:
            If None, '<in_filename>.enc' will be used.

        chunksize:
            Sets the size of the chunk which the function
            uses to read and encrypt the file. Larger chunk
            sizes can be faster for some files and machines.
            chunksize must be divisible by 16.
    """
    if not out_filename:
        out_filename = in_filename + '.enc'

    iv = ''.join(chr(random.randint(0, 0xFF)) for i in range(16))
    encryptor = AES.new(key, AES.MODE_CBC, iv)
    filesize = os.path.getsize(in_filename)

    with open(in_filename, 'rb') as inFile:
        with open(out_filename, 'wb') as outFile:
            outFile.write(struct.pack('<Q', filesize))
            outFile.write(iv)

            while True:
                chunk = inFile.read(chunksize)
                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    chunk += ' ' * (16 - len(chunk) % 16)

                outFile.write(encryptor.encrypt(chunk))
    print("Encrypted.")

def AES_decrypt_file(key, in_filename, out_filename=None, chunksize=24*1024):
    """ Decrypts a file using AES (CBC mode) with the
        given key. Parameters are similar to encrypt_file,
        with one difference: out_filename, if not supplied
        will be in_filename without its last extension
        (i.e. if in_filename is 'aaa.zip.enc' then
        out_filename will be 'aaa.zip')
    """
    if not out_filename:
        out_filename = os.path.splitext(in_filename)[0]

    with open(in_filename, 'rb') as infile:
        origsize = struct.unpack('<Q', infile.read(struct.calcsize('Q')))[0]
        iv = infile.read(16)
        decryptor = AES.new(key, AES.MODE_CBC, iv)

        with open(out_filename, 'wb') as outFile:
            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                outFile.write(decryptor.decrypt(chunk))

            outFile.truncate(origsize)
    print("Decrypted.")

#DES
def DES3_encrypt_file(key, in_filename, out_filename=None, chunksize=64*1024):
    if not out_filename:
        out_filename = in_filename + '.enc'

    iv = ''.join(chr(random.randint(0, 0xFF)) for i in range(8))
    encryptor = DES3.new(key, DES3.MODE_CFB, iv)
    filesize = os.path.getsize(in_filename)

    with open(in_filename, 'rb') as infile:
        with open(out_filename, 'wb') as outfile:
            outfile.write(struct.pack('<Q', filesize))
            outfile.write(iv)

            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    chunk += ' ' * (16 - len(chunk) % 16)

                outfile.write(encryptor.encrypt(chunk))
    print("Encrypted.")

def DES3_decrypt_file(key, in_filename, out_filename=None, chunksize=24*1024):
    if not out_filename:
        out_filename = os.path.splitext(in_filename)[0]

    with open(in_filename, 'rb') as infile:
        origsize = struct.unpack('<Q', infile.read(struct.calcsize('Q')))[0]
        iv = infile.read(8)
        decryptor = DES3.new(key, DES3.MODE_CFB, iv)

        with open(out_filename, 'wb') as outfile:
            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                outfile.write(decryptor.decrypt(chunk))

            outfile.truncate(origsize)
    print("Decrypted.")


#RSA
def encrypt_blob(public_key, in_filename, out_filename=None):
    if not out_filename:
        out_filename = in_filename + '.enc'

    with open(in_filename, 'rb') as infile:
        blob = infile.read()

    #Import the Public Key and use for encryption using PKCS1_OAEP
    rsa_key = RSA.importKey(public_key)
    rsa_key = PKCS1_OAEP.new(rsa_key)

    #compress the data first
    blob = zlib.compress(blob)

    #In determining the chunk size, determine the private key length used in bytes
    #and subtract 42 bytes (when using PKCS1_OAEP). The data will be in encrypted
    #in chunks
    chunk_size = 470
    offset = 0
    end_loop = False
    encrypted =  ""

    while not end_loop:
        #The chunk
        chunk = blob[offset:offset + chunk_size]

        #If the data chunk is less then the chunk size, then we need to add
        #padding with " ". This indicates the we reached the end of the file
        #so we end loop here
        if len(chunk) % chunk_size != 0:
            end_loop = True
            chunk += " " * (chunk_size - len(chunk))

        #Append the encrypted chunk to the overall encrypted file
        encrypted += rsa_key.encrypt(chunk)

        #Increase the offset by chunk size
        offset += chunk_size

    #Base 64 encode the encrypted file
    with open(out_filename, 'wb') as outfile:
        outfile.write(base64.b64encode(encrypted))
    # return base64.b64encode(encrypted)
    print("Encrypted.")

def decrypt_blob(private_key, in_filename, out_filename=None):
    if not out_filename:
        out_filename = 'Decrypted' + os.path.splitext(in_filename)[0]

    with open(in_filename, 'rb') as infile:
        encrypted_blob = infile.read()

    #Import the Private Key and use for decryption using PKCS1_OAEP
    rsakey = RSA.importKey(private_key)
    rsakey = PKCS1_OAEP.new(rsakey)

    #Base 64 decode the data
    encrypted_blob = base64.b64decode(encrypted_blob)

    #In determining the chunk size, determine the private key length used in bytes.
    #The data will be in decrypted in chunks
    chunk_size = 512
    offset = 0
    decrypted = ""

    #keep loop going as long as we have chunks to decrypt
    while offset < len(encrypted_blob):
        #The chunk
        chunk = encrypted_blob[offset: offset + chunk_size]

        #Append the decrypted chunk to the overall decrypted file
        decrypted += rsakey.decrypt(chunk)

        #Increase the offset by chunk size
        offset += chunk_size

    #return the decompressed decrypted data
    with open(out_filename, 'wb') as outfile:
        outfile.write(zlib.decompress(decrypted))
    # return zlib.decompress(decrypted)
    print("Decrypted.")

