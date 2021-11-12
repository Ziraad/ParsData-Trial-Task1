from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, create_refresh_token, jwt_required, get_jwt_identity
from os import urandom
import pymssql

app = Flask(__name__)
app.config["JWT_SECRET_KEY"] = "ftdsrxcsadch"
# app.secret_key = urandom(24)

host = "ZIRAAD"
server="ZIRAAD"
user = "sa"
password = "1234"
database = "testdb"

jwt = JWTManager(app)


@app.route('/login', methods=['POST'])
def login():
    if not request.is_json:
        return {'error': 'Json Only!'}, 401

    try:
        args = request.get_json()

        phone = args.get('phone_number')
        password = args.get('password')

        user = {'phone': '09169640460', 'password': '12345'}

        assert phone and password, 'Input Incorrect'

        assert phone == user['phone'] and password == user['password'], 'phone_number or password not match! or user not found'

    except Exception as e:
        return jsonify(msg=str(e)), 400

    access_token = create_access_token(identity=phone, fresh=True)
    refresh_token = create_refresh_token(identity=phone)

    return jsonify(access_token=access_token, refresh_token=refresh_token), 200


@app.route('/profile', methods=['GET'])
@app.route('/profile/<int:user_id>', methods=['GET'])
def get_profile(user_id=None):
    try:
        with pymssql.connect(host=host, server=server, user=user, password=password, database="testdb") as conn:
            with conn.cursor(as_dict = True) as cursor:

                if user_id is not None:
                    cursor.execute('SELECT * FROM users WHERE user_id=%d', user_id)  
                    cursor.callproc('GetUser', ('%s'%user_id,))
                    current_user = cursor.fetchone()

                else:
                    cursor.execute('SELECT user_id, username, phone_number, bio, avatar FROM users')
                    cursor.callproc('GetUsers')

                    current_user = cursor.fetchall()
                conn.commit()
                
                return jsonify(current_user), 200
    except:
        return jsonify(error="Something went wrong"), 400


@app.route('/edit', methods=['PUT'])
@jwt_required()
def write_profile():
    if not request.is_json:
        return {'error': 'Json Only!'}, 401

    current_user1 = get_jwt_identity()

    args = request.get_json()

    phone_number = args.get('phone_number')

    try:
        with pymssql.connect(host=host, server=server, user=user, password=password, database='testdb') as conn:
            with conn.cursor(as_dict = True) as cursor:
                cursor.execute('SELECT * FROM users WHERE phone_number=%s', phone_number)
                current_user = cursor.fetchone()
                cursor.callproc('Update_user', 
                    (
                        current_user1, 
                        request.json.get('username', current_user['username']), 
                        request.json.get('phone_number', current_user['phone_number']), 
                        request.json.get('bio', current_user['bio']),
                    )
                )
                conn.commit()
                
                return jsonify(msg='update successfully'), 200

    except Exception as e:
        return jsonify(msg='Something went wrong => ' + str(e)), 400

if __name__ == '__main__':
    app.run(debug=True)