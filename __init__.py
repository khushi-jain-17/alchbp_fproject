from flask import Flask
from flask_sqlalchemy import SQLAlchemy 
# from flask_bcrypt import Bcrypt

app = Flask(__name__)

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///test.db"
db = SQLAlchemy(app)

app.config['SECRET_KEY'] = "this is secret"

# bcrypt = Bcrypt(app)

