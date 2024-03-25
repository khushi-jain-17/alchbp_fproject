from flask import Flask
from flask_sqlalchemy import SQLAlchemy 


app = Flask(__name__)

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///test.db"
db = SQLAlchemy(app)

app.config['SECRET_KEY'] = "this is secret"

