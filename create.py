from sqlite3 import IntegrityError
from validation import * 
from flask import request,jsonify, Blueprint 
from flask_bcrypt import bcrypt
from flask_bcrypt import Bcrypt
from flask_bcrypt import  generate_password_hash
from flask_bcrypt import check_password_hash
from datetime import datetime, timedelta
import jwt 
from __init__ import app
from models import * 
from token_gen import token_required

auth_routes = Blueprint("auth_routes", __name__)

bcrypt = Bcrypt(app)

@auth_routes.route('/signup',methods=['POST'])
def signup():
    user_schema = UserSchema()
    try:
        validated_data = user_schema.load(request.json)
    except ValidationError as e:
        return jsonify({'error': e.messages}), 400
    existing_user = User.query.filter_by(email=validated_data['email']).first()
    if existing_user:
        return jsonify({'error': 'User already exists'}), 400
    hashed_password = bcrypt.generate_password_hash(validated_data['password']).decode('utf-8')
    new_user = User(uname=validated_data['uname'], email=validated_data['email'], 
                    password=hashed_password, role_id=validated_data['role_id'])
    try:
        db.session.add(new_user)
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        return jsonify({'error': 'Username or email already exists'}), 400
    
    serialized_user = user_schema.dump(new_user)
    return jsonify(serialized_user), 201

@auth_routes.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    if 'email' not in data or 'password' not in data:
        return jsonify({'error': 'Email or password missing'}), 400
    user = User.query.filter_by(email=data['email']).first()
    rid = User.query.filter_by(email=data['email']).first()
    if not user:
        return jsonify({'error': 'User does not exist'}), 401
    hashed_password = user.password
    if bcrypt.check_password_hash(hashed_password, data['password']):
        token = jwt.encode({'email': user.email, 'role_id': rid.role_id,'exp': datetime.utcnow() + timedelta(minutes=50)}, app.config['SECRET_KEY'], algorithm='HS256')
        return jsonify({'message': 'Login successful', 'token': token ,"role_id": rid.role_id}), 200
    else:
        return jsonify({'error': 'Invalid email or password'}), 401
    

blacklist = set()

@auth_routes.route('/logout', methods=['POST'])
@token_required
def logout():
    token = request.headers.get('Authorization')
    if token:
        token = token.split()[1]
        blacklist.add(token)
        return jsonify({'message': 'logged out'}), 200
    else:
        return jsonify({'error': 'token is missing'}), 403



