from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
import jwt
from datetime import datetime, timedelta
from functools import wraps

app = Flask(__name__)

# Configure MySQL database connection
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://root:root@localhost/jwt'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your_secret_key'

# Initialize extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# Define User model
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)

# Create the table
with app.app_context():
    db.create_all()

# JWT helper functions
def generate_token(user_id):
    token = jwt.encode(
        {'user_id': user_id, 'exp': datetime.utcnow() + timedelta(hours=24)},
        app.config['SECRET_KEY'],
        algorithm="HS256"
    )
    return token

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('token')
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.get(data['user_id'])
        except:
            return jsonify({'message': 'Token is invalid!'}), 401
        return f(current_user, *args, **kwargs)
    return decorated

# Register endpoint
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()
    if user:
        return jsonify({'message': 'Username already exists!'}), 400

    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    new_user = User(username=data['username'], password=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'User registered successfully!'}), 201

# Login endpoint
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()
    if not user:
        return jsonify({'message': 'User not found!'}), 401

    if bcrypt.check_password_hash(user.password, data['password']):
        token = generate_token(user.id)
        return jsonify({'token': token}), 200
    else:
        return jsonify({'message': 'Invalid credentials!'}), 401

# Protected route
@app.route('/dashboard', methods=['GET'])
@token_required
def dashboard(current_user):
    return jsonify({'message': f'Welcome {current_user.username}! This is your dashboard.'})

# Run the Flask app
if __name__ == '__main__':
    app.run(debug=True)
