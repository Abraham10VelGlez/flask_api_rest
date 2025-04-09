from flask_sqlalchemy import create_engine
from flask_sqlalchemy.ext.declarative import declarative_base
from flask_sqlalchemy import sessiononmaker
from dotenv import load_dotenv
import os
from flask import Flask

load_dotenv()  # Carga el archivo .env

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')

conexion = os.getenv('FLASK_BD_NEON_URL')

Base = declarative_base()


engine = create_engine(conexion)

Session = sessiononmaker(bind=engine)