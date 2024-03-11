from flask import request, session, jsonify, send_file, make_response
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError
import traceback
from functools import wraps
from config import app, db, api
from models import User
from config import Flask, SQLAlchemy, db
from logic import send_email
import os

# HTTP Constants
HTTP_SUCCESS = 200
HTTP_CREATED = 201
HTTP_NO_CONTENT = 204
HTTP_UNAUTHORIZED = 401
HTTP_NOT_FOUND = 404
HTTP_BAD_REQUEST = 400
HTTP_CONFLICT = 409
HTTP_SERVER_ERROR = 500
HTTP_UNPROCESSABLE_ENTITY = 422

def authorized(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if 'user_id' not in session:
            return make_response(jsonify({'error': 'Not authorized'}), HTTP_UNAUTHORIZED)
        return func(*args, **kwargs)
    return wrapper

@app.route('/forgot_password', methods=['POST'])
def forgot_password(self):
    json = request.get_json()

    user = User.query.filter_by(email=json['email']).first()

    if not user:
        return jsonify({'error': 'the email you entered was not recognized'}), HTTP_UNAUTHORIZED

    user.code = user.generate_code
    db.session.add(user)
    db.session.commit()

    subject, body, to_address = user.generate_forgot_password_email
    send_email(to_address, subject, body)

    session['user_id'] = user.id
    return jsonify({'success_message': 'Sent an email'}), HTTP_SUCCESS

@app.route('/reset_password', methods=['POST'])
def reset_password(self):
    json = request.get_json()

    user = User.query.filter_by(id=session['user_id']).first()

    if not user.code == json['code']:
        return jsonify({'error': 'code is incorrect'}), HTTP_UNAUTHORIZED

    return jsonify({'success_message': 'code is correct!'}), HTTP_SUCCESS


@app.route('/signup', methods=['POST'])
def signup(self):
    if request.method == 'POST':
        json = request.get_json()

        if not json['email'] or not json['first_name'] or not json['last_name']:
            return make_response(jsonify({'error': 'First name, last name, email, and password are required fields'}), HTTP_BAD_REQUEST)

        try: 
            user = User(
                email=json.get('email'),
                linked_in=json.get('linked_in'),
                first_name=json.get('first_name'),
                last_name=json.get('last_name'),
                disability=json.get('disability'),
                country=json.get('country')
            )

            user.password_hash = json.get('password')
            db.session.add(user)
            db.session.commit()

            session['user_id'] = user.id
            user_dict = user.to_dict()
            return user_dict, HTTP_CREATED
        except IntegrityError:
            # Handle IntegrityError...
            return {'error': 'A user with these details already exists'}, HTTP_CONFLICT

        except ValueError as ve:
                # Handle ValueError which might be raised during inappropriate data assignment...
                return {'error': f'Value error: {str(ve)}'}, HTTP_BAD_REQUEST

        except Exception as e:
                # Handle any other exceptions...
                return {'error': 'An unexpected error occurred'}, HTTP_SERVER_ERROR


@app.route('/auth', methods=['GET', 'POST', 'DELETE'])
@authorized
def auth(self):
    if request.method == 'GET':
        if 'user_id' in session:
            user = User.query.filter(User.id == session['user_id']).first()
            if user:
                user_dict = user.to_dict()
                return user_dict, HTTP_SUCCESS

        return {"error": "you are not logged in"}, 404
    if request.method == 'POST':
        # retrieve the request values
        # determine if we have a user in the db with that email 
        # authenticate password
        # if not return error, if so return user and set session
        req_values = request.get_json()
        if not req_values or 'email' not in req_values or 'password' not in req_values:
            return jsonify({"error": "Invalid request"}), HTTP_BAD_REQUEST

        user = User.query.filter_by(email=req_values['email']).first()
        if user and user.authenticate(req_values['password']):
            session['user_id'] = user.id
            user_dict = user.to_dict()
            return user_dict, HTTP_CREATED
        else:
            return {'error': 'Wrong email or password'}, 401
    elif request.method == 'DELETE':
        user = User.query.filter(User.id == session['user_id']).first() and session['user_id']

        if user: 
            session['user_id'] = None
            return {}, HTTP_NO_CONTENT
        else:
            return {'error': 'Unauthorized'}, HTTP_UNAUTHORIZED

if __name__ == '__main__':
    app.run(port=5555, debug=True)