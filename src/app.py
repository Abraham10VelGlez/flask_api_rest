from flask import Flask, jsonify
from config import Config
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from routes import register_routex

app = Flask(__name__)
app.config.from_object(Config)
# PERMITE PETICIONES DESDE EL FRONT
# CORS(app, origins="http://localhost:5175", supports_credentials=True) -------------- viteapp conexion docker 5175
CORS(
    app, origins="http://localhost:5173", supports_credentials=True
)  # ---------- para la app de quantum 5173
jwt = JWTManager(app)
# funcion de rutas para funcion inicial del API REST
register_routex(app)

# Start the Server
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
