#!/usr/bin/python 

import os
import sys

from cryptography.hazmat.primitives.ciphers import (Cipher, algorithms, modes)
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


authenticationString = "NaveenYanamaddiNetworkSecur!ty2PS"
def usage():
    print "Usage Error"
    print "Encryption Usage: python fcrypt.py -e destination_public_key_filename sender_private_key_filename input_plaintext_file ciphertext_file"
    print "Decryption Usage: python fcrypt.py -d destination_private_key_filename sender_public_key_filename ciphertext_file output_plaintext_file"

def encryptDataWithAES(key,dataFromFile,authenticationString):

    iv = os.urandom(32)
    
    encryptor = Cipher(algorithms.AES(key),modes.GCM(iv),backend=default_backend()).encryptor()
    encryptor.authenticate_additional_data(authenticationString)
    ciphertext = encryptor.update(dataFromFile) + encryptor.finalize()
    return (iv, ciphertext, encryptor.tag)

def EncryptData():
    
    key = os.urandom(32) #generate random key size of 64 bytes
    
    # Reading from plain text file
    # Encrypting the text using AES algorithm
    try:
        inputTextFile = open(sys.argv[4], "rb")
        dataFromFile  = inputTextFile.read()
        iv, cipherText, encryptorTag = encryptDataWithAES(key,dataFromFile,authenticationString) #encrypt the data from plain text file
    except:
        print "Error in accessing the file"
        sys.exit(1)
    
    # Read the Keys from files 
    try:
        # Read Destination Publick Key and serialize into bytes
        destinationPublicKeyFile = open(sys.argv[2], "rb")
        with destinationPublicKeyFile as publicKey:
            destinationPublicKey = serialization.load_der_public_key(
                                publicKey.read(),
                                backend = default_backend()
                        )

        # Read Sender's private key and serialize into bytes
        senderPrivateKeyFile = open(sys.argv[3], "rb")
        with senderPrivateKeyFile as privateKey:
            senderPrivateKey = serialization.load_der_private_key(
                                privateKey.read(),
                                password = None,
                                backend = default_backend()
                        )

    except:
        print "Error in Reading Keys"
        sys.exit(1)

    # Encrypt the AES key using destination Public key
    try:
        cipherKey = destinationPublicKey.encrypt(key,
                    padding.OAEP(mgf = padding.MGF1(algorithm = hashes.SHA512()),
                                 algorithm = hashes.SHA512(),
                                 label = None
                                )
                    )
    except: 
        print "Error in Encrypting the key"
        sys.exit(1)

    # Sign the data using sender's private key

    try:
        signingKey = senderPrivateKey.signer(
                     padding.PSS(mgf = padding.MGF1(hashes.SHA512()),
                                 salt_length = padding.PSS.MAX_LENGTH
                            ),
                            hashes.SHA512()
                     )
        signingKey.update(cipherKey)
        signature = signingKey.finalize()
    except:
        print "Error in Signing key"
        sys.exit(1)
    
    # Writing Cipher Key, IV, signing Key, authentication tag, Encrypted Data into file to be sent over email
    try:
        cipherTextFile = open(sys.argv[5], 'w+')
        cipherTextFile.write(cipherKey)
        cipherTextFile.write(":")
        cipherTextFile.write(iv)
        cipherTextFile.write(":")
        cipherTextFile.write(signature)
        cipherTextFile.write(":")
        cipherTextFile.write(encryptorTag)
        cipherTextFile.write(":")
        cipherTextFile.write(cipherText)
        cipherTextFile.flush()
        cipherTextFile.close()
    except:
        print "Error in writing file"
        sys.exit(1)

    inputTextFile.close()

def DecryptData():

    try:
        cipherTextFromFile = open(sys.argv[4], "rb")
        # Extract the Cipher Key, IV, signing Key, authentication tag, Encrypted Data from file
        cipherKey, iv,signature, encryptorTag, cipherText = cipherTextFromFile.read().split(":")
    except:

        print "Error in accessing the file"
        sys.exit(1)
    try:
	 #read the keys from argument for decrytion
        senderPublicKeyFromFile = open(sys.argv[3],"rb")
        with senderPublicKeyFromFile as publicKey:
            senderPublicKey = serialization.load_der_public_key(
                                publicKey.read(),
                                backend = default_backend()
                        )
        
        destinationPrivateKeyFromFile = open(sys.argv[2],"rb")
        with destinationPrivateKeyFromFile as privateKey:
            destinationPrivateKey = serialization.load_der_private_key(
                                privateKey.read(),
                                password = None,
                                backend = default_backend()
                        )
    except:

        print "Error in access Keys"
        sys.exit(1)

    try:
	#verify signature using sender's public key
        verifier = senderPublicKey.verifier(
                        signature,
                        padding.PSS(
                                mgf = padding.MGF1(hashes.SHA512()),
                                salt_length = padding.PSS.MAX_LENGTH
                        ),
                        hashes.SHA512()
                )
        verifier.update(cipherKey)


        #decrypt the key using the destination' private key     
        decryptedKey = destinationPrivateKey.decrypt(
                        cipherKey,
                        padding.OAEP(
                                mgf = padding.MGF1(algorithm = hashes.SHA512()),
                                algorithm = hashes.SHA512(),
                                label = None
                        )
                )
    except:
        print "Error in verifying keys"
        sys.exit(1)

    try:
        outputText = open(sys.argv[5], "w+")
        outputText.write(decryptData(decryptedKey,authenticationString,iv,cipherText,encryptorTag))
        outputText.flush()
        outputText.close()
    except:
        print "Error in writing out file"
        sys.exit(1)
        
def main():

    if(len(sys.argv) < 5):
        usage()
        sys.exit(1)
    if (sys.argv[1] not in ['-e','-d']):
        usage()
        sys.exit(1)
    if sys.argv[1] == '-e':
        EncryptData()
    elif sys.argv[1] == '-d':
        DecryptData()
main()
