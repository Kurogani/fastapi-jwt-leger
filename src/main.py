from fastapi import FastAPI, Depends, HTTPException
from .auth import AuthHandler
from pydantic import BaseModel

app = FastAPI()

class AuthDetails(BaseModel): #simulador del modelo
    username: str
    password: str

auth_handler = AuthHandler()
users = [] #array en el que se almacenan los usuarios, esto simula la tabla users en una db

@app.get('/getAllUsersSinToken') #get de todos los usuarios sin proteccion
def getAllUsersSinToken():
    return users

@app.get('/getAllUsersConToken') #get de todos los usuario
def getAllUsersConToken(username=Depends(auth_handler.auth_wrapper)):
    return users

@app.post('/register', status_code=200)
def register(auth_details: AuthDetails):
    if any(x['username'] == auth_details.username for x in users):
        raise HTTPException(status_code=400, detail='Este usuario ya existe.')

    hashed_password = auth_handler.get_password_hash(auth_details.password)
    users.append({
        'username': auth_details.username,
        'password': hashed_password    
    })
    return "Usuario registrado con exito."


@app.post('/login')
def login(auth_details: AuthDetails):
    user = None
    for x in users:
        if x['username'] == auth_details.username:
            user = x
            break
    
    if (user is None) or (not auth_handler.verify_password(auth_details.password, user['password'])):
        raise HTTPException(status_code=401, detail='Credenciales Invalidas')
    token = auth_handler.encode_token(user['username'])
    return { 'token': token }
