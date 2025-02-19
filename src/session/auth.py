from flask import Blueprint, request, jsonify
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity

authsession_xuser = Blueprint("auth", __name__)

# Base de datos simulada
USERS = {"chicopython": "secret"}

# Login
@authsession_xuser.route("/logsession", methods=["POST"])
def login():
    #recibimos un json de los datos del usuario, 
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    if USERS.get(username) == password:
        #si las credenciales coinciden
        token = create_access_token(identity=username)
        #se retorna un token resultante
        return jsonify({"token": token}), 200
    #si no retorna un error
    return jsonify({"error": "Credenciales inválidas"}), 401

# Ruta protegida
@authsession_xuser.route("/inicio_a", methods=["GET"])
#requerido el jwttoken
@jwt_required()
def protected():
    current_user = get_jwt_identity()
    return jsonify({"message": f"Hola, {current_user}. Estás autenticado."})

