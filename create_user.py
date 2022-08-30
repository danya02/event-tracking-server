from database import *
import getpass
import hashlib
import secrets

user_name = input('Enter your username: ')
password = getpass.getpass('Enter your password: ')
salt = secrets.token_bytes(32)
N = 16384
r = 8
p = 1
scrypt_hash = hashlib.scrypt(password.encode(), salt=salt, n=N, r=r, p=p)
u = User()
u.username = user_name
u.scrypt_hash = scrypt_hash
u.scrypt_salt = salt
u.scrypt_N = N
u.scrypt_r = r
u.scrypt_p = p
u.save()
