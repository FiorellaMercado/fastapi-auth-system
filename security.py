import bcrypt
import jwt
import os
from datetime import datetime, timezone, timedelta
import secrets
from cryptography.fernet import Fernet
from dotenv import load_dotenv



def hash_password(password):
   password_bytes=password.encode('utf-8')

   sal=bcrypt.gensalt()

   hash_bytes=bcrypt.hashpw(password_bytes, sal)

   return hash_bytes.decode('utf-8')

def verificar_password(password, password_hash):

    password_bytes=password.encode('utf-8')
    hash_bytes=password_hash.encode('utf-8')

    return bcrypt.checkpw(password_bytes, hash_bytes)


load_dotenv()

KEY_SECRET=os.getenv('JWT_KEY_SECRET')
JWT_ALGORITHM=os.getenv('JWT_ALGORITHM')
JWT_EXPIRE_MINUTES=os.getenv('JWT_EXPIRE_MINUTES')
def crear_jwt(datos):
    exp_time=datetime.now(timezone.utc)+timedelta(minutes=int(JWT_EXPIRE_MINUTES))
    datos_copia=datos.copy()
    datos_copia['exp']=exp_time
    
    token=jwt.encode(datos_copia, KEY_SECRET,algorithm=JWT_ALGORITHM)
    return token

def verificar_jwt(token):
    decoded_token=jwt.decode(token, KEY_SECRET,algorithms=[JWT_ALGORITHM])
    return decoded_token


def generar_session_id():
    session_id=secrets.token_urlsafe(32)
    return session_id

def generar_csrf_token():
    csrf_token=secrets.token_urlsafe(32)
    return csrf_token

ENCRYPTION_KEY=os.getenv('ENCRYPTION_KEY')

objeto=Fernet(ENCRYPTION_KEY)

def cifrar_dato(dato):
    dato_bytes=dato.encode('utf-8')
    dato_cifrado=objeto.encrypt(dato_bytes)
    return dato_cifrado.decode('utf-8')


def descifrar_dato(dato):
    dato_bytes=dato.encode('utf-8')
    dato_decifrado=objeto.decrypt(dato_bytes)
    return dato_decifrado.decode('utf-8')
