from flask import Blueprint 
from myrole import * 
import jwt 
from models import User 
from flask import request,jsonify
from token_gen import token_required


routes = Blueprint("routes", __name__)


@routes.route('/get_admin', methods=['GET'])
@token_required
def get_admin():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'error': 'token is missing'}), 403
    try:
        token = token.split(" ")[1]
        payload = jwt.decode(
            token, app.config['SECRET_KEY'], algorithms=['HS256'])
        role_id = payload.get('role_id')
        print(role_id)
        if role_id == 2:
            users = User.query.filter_by(role_id=role_id).all()
            user_data = [{'uname': user.uname,'email':user.email,'password':user.password,'role_id':user.role_id} for user in users]
            return jsonify(user_data)
        else:
            return jsonify({'error': 'insufficient permission'})
    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'token has expired'}), 403
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid Token'}), 403


@routes.route('/get_user', methods=['GET'])
@token_required
def get_user():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'error': 'Token is missing'}), 403
    try:
        token = token.split(" ")[1]
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        role_id = payload.get('role_id')
        print(role_id)
        if role_id == 1:  
            users = User.query.filter_by(role_id=role_id).all()
            user_data = [{ 'uname': user.uname, 'email': user.email, 'role_id': user.role_id} for user in users]
            return jsonify(user_data)
        else:
            return jsonify({'error': 'Insufficient permission'}), 403
    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token has expired'}), 403
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid Token'}), 403


