from flask import Blueprint, jsonify
from session.auth import authsession_xuser

api_rest = Blueprint("main", __name__)


@api_rest.route("/", methods=["GET"])
def home():
    return jsonify({"message": "🐍 Bienvenido a la API REST PYTHON 🐍"})


@api_rest.route("/abc", methods=["GET"])
def view1():
    return "VISTA LIBRE DEL API DE FLASK PYTHON"


def register_routex(app):
    # ruta inicial del api rest
    app.register_blueprint(api_rest)
    # ruta de autentificacion
    app.register_blueprint(authsession_xuser, url_prefix="/auth")
