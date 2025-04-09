from flask import Blueprint, request, jsonify
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
import os
from dotenv import load_dotenv
import jwt
from flask import request, jsonify
# from models.Userx import Userx

# from app import db  # importa la instancia de la base de datos

authsession_xuser = Blueprint("auth", __name__)

# Base de datos simulada
USERS = {"igecem_especialista284_avg@avg.edomex.com": "$secr4Toa"}

# Login
@authsession_xuser.route("/logsession", methods=["POST"])
# de lado del cliente
#REQUEST {
  #  "username": "chicopython",
 #   "password": "secret"
#}

def login():
    #recibimos un json de los datos del usuario, 
    data = request.get_json()
    #extrayendo datos de vite post
    values = data.get("values", {})
    #username = data.get("username")
    #password = data.get("password")
    username = values.get("u")
    password = values.get("p")    
    #validamos si  hay campos vacios
    if not username or not password:
        #return jsonify({"error": "Faltan datos"}), 400
        return jsonify({"error": 00}), 400 #00
    #validamos si existen campos 
    if username in USERS:
        if USERS.get(username) == password:
            #si las credenciales coinciden
            token = create_access_token(identity=username)
            #se retorna un token resultante
            #return jsonify({"token": token,  "user": username, "password": password}), 200
            return jsonify({"token": token}), 200
    #si no retorna un error
    #return jsonify({"error": "Credenciales inválidas"}), 401 #0
    return jsonify({"error": 0}), 401 #0

# Ruta protegida, SOLO SE PUEDE ACCEDER A ELLA MEDIANTE TOKEN DEL LADO DEL SERVIDOR
@authsession_xuser.route("/inicio_a", methods=["GET"])
#PARA HACER USP DE LA RUTA NECSEITAS HEADERS:   KEY=Authorization  VALUE=Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTc0MDYwNzk0NSwianRpIjoiMDY4MDgwMDMtMGNhZi00N2Q0LTlmZGItNThiYzAzYzU3MWJiIiwidHlwZSI6ImFjY2VzcyIsInN1YiI6ImNoaWNvcHl0aG9uIiwibmJmIjoxNzQwNjA3OTQ1LCJjc3JmIjoiN2UwMDdlOTMtMjEyZC00NzdjLTk5MGEtZjUwZjIyNDJiYzllIiwiZXhwIjoxNzQwNjA4ODQ1fQ.Lz0Zrge85EaI1m0Tz3FSR7qwolZ0g39bojP5ZwR7CD8 TOKEN QUE ME RESULTE DE /logsession
#requerido el jwttoken
@jwt_required()
def protected():
    current_user = get_jwt_identity()
    return jsonify({"message": f"Hola, {current_user}. Estás autenticado, en el apirest"})
#resultado devulve un json donde verifca que esa ruta esta autenficada por el token
#{
    #"message": "Hola, chicopython. Estás autenticado."
#}

#VALIDACION DEL TOKEN DEL LADO DEL BACKEND
@authsession_xuser.route("/verificatoken",methods=["GET"])
#SECRET_KEY = 
def token_user():
    #llamad de Env    
    load_dotenv()
    SECRET_KEY = os.getenv("JWT_SECRET_KEY")
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        return jsonify({"msg": "Peligro Autorizacion incorrecta de header"}), 401
    
    try:
        token = auth_header.split(" ")[1]  # Separa "Bearer" del token
        decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return decoded  # Si es válido, devuelve los datos
    except jwt.ExpiredSignatureError:
        return jsonify({"messageabraham": "Token expirado"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"messageabraham": "Token inválido"}), 401
    
    #retorna una validacion del token y el nombre del token user en sub
    """
    {
    "csrf": "7e007e93-212d-477c-990a-f50f2242bc9e",
    "exp": 1740608845,
    "fresh": false,
    "iat": 1740607945,
    "jti": "06808003-0caf-47d4-9fdb-58bc03c571bb",
    "nbf": 1740607945,
    "sub": "chicopython",
    "type": "access"
}
"""


# ELIMINAR O LIMPIAR EL TOKEN DE BACKEND ES COMO CERRAR SESION

# REGISTRAR UN NUEVO USUARIO FLASK A NEON
@authsession_xuser.route('/newflask', methods=["POST"])
def newuserx():    
     #recibimos un json de los datos del usuario, 
    data = request.get_json()
    #extrayendo datos de vite post
    values = data.get("values", {})
    name = values.get("uname")
    username = values.get("u")
    password = values.get("p")    
    #validamos si  hay campos vacios
    if not username or not password or not name:
        #return jsonify({"error": "Faltan datos"}), 400
        return jsonify({"error": 00}), 400 #00
    #validamos si existen campos  en la base de datos
    # existeuser = Userx.query.filter_by(nombre_usuario=username).first()
    
    # if existeuser:
    #     return jsonify({"error": "Usuario ya existe"}), 409  # 409 Conflict

    # # Si no existe, puedes registrarlo (opcional)
    # newavguser = Userx(nombrex=name,nombre_usuario=username, pasword=password,rol=1)
    # db.session.add(newavguser)
    # db.session.commit()

    # return jsonify({"msg": "Usuario creado correctamente"}), 201
    
    
    return jsonify({"msg": username, "msg2": password, "msg3": name}), 200
    # return jsonify({"msg": existeuser}), 200

