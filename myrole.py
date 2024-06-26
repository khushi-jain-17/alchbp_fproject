import jwt 
from flask import request,jsonify
from functools import wraps 
from __init__ import app 
from  models import * 


def role_required(role_id):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            token = request.headers.get('Authorization')
            if token:
                try:
                    token = token.split(" ")[1]
                    payload = jwt.decode(
                        token, app.config['SECRET_KEY'], algorithms=["HS256"])
                    user_role = payload.get('role_id')
                    if user_role == role_id:
                        return func(*args, **kwargs)
                    else:
                        return jsonify({'error': 'insufficient permission'})
                except jwt.ExpiredSignatureError:
                    return jsonify({'error': 'Token has expired'}), 401
                except jwt.InvalidTokenError:
                    return jsonify({'error': 'Token is invalid'}), 401
            else:
                return jsonify({'error': 'Token is missing'}), 401
        return wrapper
    return decorator
