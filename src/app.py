from flask import Flask, jsonify
from user import user
from config import Config
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from routes import register_routex

app = Flask(__name__)
app.config.from_object(Config)

#PERMITE PETICIONES DESDE EL FRONT
CORS(app)
jwt = JWTManager(app)
#funcion de ruotes para funcion inicial del API REST
register_routex(app)

# Start the Server
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)