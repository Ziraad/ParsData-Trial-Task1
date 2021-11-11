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

        phone = args.get('phone')
        password = args.get('password')

        user = {'phone': '09169640460', 'password': '12345'}

        assert phone and password, 'Input Incorrect'

        assert phone == user['phone'] and password == user['password'], 'phone or password not match! or user not found'

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
                    cursor.execute("""
                    CREATE PROCEDURE GetUser
                    @user_id int
                    AS BEGIN
                        SELECT * FROM users WHERE user_id = @user_id
                    END
                    """)
                    cursor.callproc('GetUser', ('%s'%user_id,))

                else:
                    cursor.execute("""
                    CREATE PROCEDURE GetUsers
                    AS
                        SELECT user_id, username, phone_number, bio, avatar FROM users
                    
                    """)
                    cursor.callproc('GetUsers')

                current_user = [
                    {
                        "user_id":row['user_id'],  
                        "username":row['username'], 
                        "phone_number":row['phone_number'], 
                        "bio":row['bio'],
                        "avatar":row['avatar']
                    } 
                    for row in cursor]
                
                return jsonify(current_user)

    except:
        return jsonify(error="Something went wrong"), 400


@app.route('/edit', methods=['POST'])
@jwt_required()
def write_profile():
    if not request.is_json:
        return {'error': 'Json Only!'}, 401

    current_user = get_jwt_identity()

    args = request.get_json()
    
    return jsonify(updated=current_user)



if __name__ == '__main__':
    app.run(debug=True)