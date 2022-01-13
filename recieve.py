import requests
from decouple import config
from tqdm import tqdm
import time
from cryptography.fernet import Fernet
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

API_KEY = config('READ_URI')

msg=requests.get(API_KEY)
msg=msg.json()['feeds'][-1]['field1']
# password_provided = input("Provide the key : ")
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
f=Fernet(key)
for i in tqdm(range(0,10), desc="Receiving"):
    time.sleep(0.00001)
msg=msg[2:-1]
msg=bytes(msg,'utf-8')
msg=f.decrypt(msg)
print("\nThe Message sent was: \n\n"+msg.decode())