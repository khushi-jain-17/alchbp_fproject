from __init__ import db 


class User(db.Model):
    __tablename__ = 'users'
    
    uid = db.Column(db.Integer, primary_key=True)
    uname = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(50), nullable=False)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.rid'), nullable=False)

class Role(db.Model):
    __tablename__ = 'roles'
    
    rid = db.Column(db.Integer, primary_key=True)
    rname = db.Column(db.String(50), unique=True, nullable=False)
