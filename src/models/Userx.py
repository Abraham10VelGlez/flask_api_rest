from extensions import db

class Userx(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nombrex = db.Column(db.String(100), nullable=False)
    nombre_usuario = db.Column(db.String(100), unique=True, nullable=False)
    pasword = db.Column(db.String(100), nullable=False)
    rol = db.Column(db.Integer,nullable=False)

def __repr__(self):
    return f'<Userx {self.nombre_usuario}>'
