import jwt
from fastapi import HTTPException, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from passlib.context import CryptContext
from datetime import datetime, timedelta


class AuthHandler():
    security = HTTPBearer()
    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
    secret = 'SECRET'  #palabra secreta para el handshake

    def get_password_hash(self, password):  #hashea el password
        return self.pwd_context.hash(password)

    def verify_password(self, plain_password, hashed_password): #valida que el password sea el correcto
        return self.pwd_context.verify(plain_password, hashed_password)

    def encode_token(self, user_id):
        payload = {
            'exp': datetime.utcnow() + timedelta(days=0, minutes=10), #tiempo de vida del token en minutos o dias
            'iat': datetime.utcnow(),
            'sub': user_id
        }
        return jwt.encode(
            payload,
            self.secret,
            algorithm='HS256' #metodo de encriptado
        )

    def decode_token(self, token):
        try:
            payload = jwt.decode(token, self.secret, algorithms=['HS256'])
            return payload['sub']
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail='Token Expirado.') #si el token se vence lanza este error
        except jwt.InvalidTokenError as e:
            raise HTTPException(status_code=401, detail='Token Invalido.') #si se intenta hacer un request con un token invalido

    def auth_wrapper(self, auth: HTTPAuthorizationCredentials = Security(security)):
        return self.decode_token(auth.credentials)
