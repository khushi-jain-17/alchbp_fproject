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


@routes.route('/users/<int:page_num>',methods=['GET'])
def user(page_num):
    users=User.query.paginate(per_page=5,page=page_num,error_out=True)
    output=[]
    for u in users:
        user_data = {
            "uname":u.uname,
            "email":u.email,
            "password":u.password,
            "role_id":u.role_id
        }
        output.append(user_data)
    return jsonify({'users':output})


@routes.route('/users',methods=['GET'])
def dynamic():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    users = User.query.paginate(page=page, per_page=per_page, error_out=True)
    output = []
    for u in users:
        user_data = {
            "uname":u.uname,
            "email":u.email,
            "password":u.password,
            "role_id":u.role_id
        }
        output.append(user_data)
    return jsonify({'users':output})

        


