from flask import Flask, jsonify
from user import user

app = Flask(__name__)

# Routes
@app.route("/python", methods=["GET"])
def ping():
    return jsonify({"response": "SERVER PYTHON API REST ABRAHAM USER AAA STUDIOA AAA"})

@app.route("/users")
def usershandler():
    return jsonify({"user": user})

#json para version
@app.route("/boy")
def userprueba():
    return jsonify({"user": user, "variablespython": "a + b = ab" })

#json para version
@app.route("/version")
def userversion():
    return jsonify({"user": user, "versionx": "Beta 1.1.1.0" })

#ruta por default
@app.route("/")
def defaview():
    return "bienvenidos al SERVER PYTHON API + FLASK "

# Start the Server
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)