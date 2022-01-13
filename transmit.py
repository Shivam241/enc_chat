import urllib.request
from decouple import config
import time
from tqdm import tqdm
from cryptography.fernet import Fernet
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

API_KEY = config('WRITE_URI')

msg=str(input('Enter your message : '))
# password_provided = input("Provide a key : ")
password_provided = 'qwerty'
password = password_provided.encode()
salt = b'salt_'
kdf = PBKDF2HMAC(
algorithm=hashes.SHA256(),
length=32,
salt=salt,
iterations=100000,
backend=default_backend()
)
key = base64.urlsafe_b64encode(kdf.derive(password))
urllib.request.urlopen
msg=msg.encode()
f = Fernet(key)
msg=f.encrypt(msg)
msg=str(msg)

print("\nEncrypting message...")
for i in tqdm(range(2), desc="Encrypting"):
    time.sleep(0.0001)

for i in tqdm(range(0,10), desc="Transmitting"):
    time.sleep(0.00001)
b=urllib.request.urlopen(API_KEY+msg)
print("\nYour message has successfully been sent with end-to-end encryption!")
