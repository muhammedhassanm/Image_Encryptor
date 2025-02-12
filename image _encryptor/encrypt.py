import os
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Hash import SHA256

def encrypt_image(key, filename):
    chunksize = 64 * 1024
    basename = os.path.splitext(os.path.basename(filename))[0]
    outputFile =  basename + "_encrypted.jpg"
    filesize = str(os.path.getsize(filename)).zfill(16)
    IV = Random.new().read(16)

    encryptor = AES.new(key, AES.MODE_CBC, IV)

    with open(filename, 'rb') as infile:
        with open(outputFile, 'wb') as outfile:
            outfile.write(filesize.encode('utf-8'))
            outfile.write(IV)

            while True:
                chunk = infile.read(chunksize)

                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    chunk += b' ' * (16 - (len(chunk) % 16))

                outfile.write(encryptor.encrypt(chunk))

def decrypt_image(key, filename):
    chunksize = 64 * 1024
    basename = os.path.splitext(os.path.basename(filename))[0]
    basename = basename.rsplit('_',1)[0]
    outputFile =  basename + "_decrypted.jpg"

    with open(filename, 'rb') as infile:
        filesize = int(infile.read(16))
        IV = infile.read(16)

        decryptor = AES.new(key, AES.MODE_CBC, IV)

        with open(outputFile, 'wb') as outfile:
            while True:
                chunk = infile.read(chunksize)

                if len(chunk) == 0:
                    break

                outfile.write(decryptor.decrypt(chunk))
            outfile.truncate(filesize)

def encrypt_text(key, text):
    
    key = getKey(password)
    IV = Random.new().read(16)
    encryptor = AES.new(key, AES.MODE_CFB, IV)
    ciphertext = encryptor.encrypt(text.encode())
    return ciphertext, IV

def decrypt_text(ciphertext, password, IV):
    key = getKey(password)
#    IV = Random.new().read(16)
    obj2 = AES.new(key, AES.MODE_CFB, IV)
    decrypttext = obj2.decrypt(ciphertext)
    return decrypttext

def getKey(password):
    hasher = SHA256.new(password.encode('utf-8'))
    return hasher.digest()

choice = input("Would you like to (E)ncrypt or (D)ecrypt?: ")
os.chdir('C:/Users/100119/Desktop/image _encryptor/images')
if choice == 'E' or choice == 'e':
    
    text = input("text to encrypt: ")
    
    filename = input("File to encrypt: ").replace("'","")

#    filename = 'C:/Users/100119/Desktop/image _encryptor/images/Balu.png'
    password = input("Password: ")
    encrypt_image(getKey(password), filename)
    ciphertext, IV = encrypt_text( password,text)
    print(ciphertext)
    choice = input("Would you like to (E)ncrypt or (D)ecrypt?: ")
    if choice == 'D' or choice == 'd':
        text = ciphertext
        filename = input("File to decrypt: ").replace("'","")
        password = str(input("Password: "))
        decrypt_image(getKey(password), filename)
        decrypt_text  = decrypt_text(text,password, IV)
        decrypt_text = decrypt_text.decode()
        print(decrypt_text)
    else:
        print("Done.")

    
elif choice == 'D' or choice == 'd':
    text = ciphertext
    filename = input("File to decrypt: ").replace("'","")
    password = str(input("Password: "))
    decrypt_image(getKey(password), filename)
    decrypt_text  = decrypt_text(text,password, IV)
    decrypt_text = decrypt_text.decode()
    print(decrypt_text)
    choice = input("Would you like to (E)ncrypt or (D)ecrypt?: ")
    if choice == 'D' or choice == 'd':
        text = input("text to encrypt: ")
        filename = input("File to encrypt: ").replace("'","")
        password = input("Password: ")
        encrypt_image(getKey(password), filename)
        ciphertext, IV = encrypt_text( password,text)
        print(ciphertext)
    else:
        print("Done.")
else:
    print("No Option selected, closing...")


    
    
  
  




