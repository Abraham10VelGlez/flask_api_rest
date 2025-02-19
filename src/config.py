# creacion de nuestro token en https://jwt.io/ 
import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "5050239920041995")
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIyMDA0MTk5NSIsIm5hbWUiOiJBYnJhaGFtMTBWZWxHbGV6IiwiaWF0IjoxOTk1MDQyMDk5fQ.EXo_tJuW2iQVd0K5Q89GV6IT9YnwxcbWgoQEsoFyASU")
