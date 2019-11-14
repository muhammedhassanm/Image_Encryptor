# -*- coding: utf-8 -*-
"""
Created on Thu Nov  7 11:16:19 2019

@author: 100119
"""
#import cryptography
from cryptography.fernet import Fernet
import base64
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

message = "hassan".encode()
password = "password".encode() 

kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt = os.urandom(16), # CHANGE THIS - recommend using a key from os.urandom(16), must be of type bytes
    iterations=100000,
    backend=default_backend()
)

key = base64.urlsafe_b64encode(kdf.derive(password)) # Can only use kdf once

encrypted_text =  Fernet(key).encrypt(message)
decrypted_text =  Fernet(key).decrypt(encrypted_text).decode()


#Image encryption
import io
from PIL import Image
from Crypto.Cipher import AES
from Crypto import Random

KEY = Random.new().read(AES.block_size)
IV = Random.new().read(AES.block_size)
PATH = 'C:/Users/100119/Desktop/image _encryptor/images/Doc_1571312765676.jpeg'
base_name = os.path.splitext(os.path.basename(PATH))[0]

#Encryption
input_file = open(PATH,'rb')
input_data = input_file.read()
input_file.close()

cfb_cipher = AES.new(KEY, AES.MODE_CFB, IV)
enc_data = cfb_cipher.encrypt(input_data)

enc_file = open("encrypted.enc", "wb")
enc_file.write(enc_data)
enc_file.close()

#Decryption
enc_file2 = open("encrypted.enc",'rb')
enc_data2 = enc_file2.read()
enc_file2.close()
cfb_decipher = AES.new(KEY, AES.MODE_CFB, IV)
plain_data = cfb_decipher.decrypt(enc_data2)


image = Image.open(io.BytesIO(plain_data))
image.save('C:/Users/100119/Desktop/image _encryptor/images/' + base_name + '_decrypted_.jpg')



