# Application-of-Cryptography
An application that can be used to encrypt and sign a file to be sent
by email. The sender knows the public key of the destination, and has a
private key to sign the file. The application can also be used by the
receiver to decrypt the file using his private key and to verify the
signature using the public key of the sender. I have designed the
application to be efficient (i.e., use a combination of public key
crypto and symmteric key crypto).

The application should operate as follows. For encryption and
signatures:

python fcrypt.py -e destination_public_key_filename
sender_private_key_filename input_plaintext_file ciphertext_file
and for decryption and signature verification:

python fcrypt.py -d destination_private_key_filename
sender_public_key_filename ciphertext_file output_plaintext_file
