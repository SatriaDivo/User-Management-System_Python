# app.py

from flask import Flask, request, jsonify, abort
from flask_jwt_extended import JWTManager, jwt_required, get_jwt_identity, create_access_token
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, UserGroup, UserGroupMembership, ActivityLog
from config import Config
import logging

app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)

with app.app_context():
    db.create_all()

jwt = JWTManager(app)

logging.basicConfig(level=logging.DEBUG)

def log_activity(user_id, activity_type, details):
    new_log = ActivityLog(user_id=user_id, activity_type=activity_type, details=details)
    db.session.add(new_log)
    db.session.commit()


# login dengan akun default "username" : "admin", "password" : "admin"
@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data or not 'username' in data or not 'password' in data:
        abort(400, description="Username and password are required")
    
    user = User.query.filter_by(username=data['username']).first()
    if not user or not check_password_hash(user.password, data['password']):
        abort(401, description="Incorrect username or password")
    
    access_token = create_access_token(identity={'user_id': user.id, 'username': user.username, 'is_admin': user.is_admin})
    return jsonify(access_token=access_token), 200


# bagian user
# membuat user
@app.route('/api/users', methods=['POST'])
@jwt_required()
def create_user():
    current_user = get_jwt_identity()
    if not current_user or not current_user['is_admin']:
        abort(403, description="Not authorized to create users")

    data = request.get_json()
    if not data or not 'username' in data or not 'password' in data:
        abort(400, description="Username and password are required")
    
    existing_user = User.query.filter_by(username=data['username']).first()
    if existing_user:
        abort(400, description="Username already exists")
    
    hashed_password = generate_password_hash(data['password'], method='pbkdf2:sha256')
    new_user = User(
        username=data['username'],
        password=hashed_password,
        fullname=data.get('fullname', ''),
        status=data.get('status', 'active')  # Status deafult adalah active
    )
    db.session.add(new_user)
    db.session.commit()
    log_activity(current_user['user_id'], 'CREATE_USER', f"Created user {new_user.username}")
    return jsonify({'message': 'User created successfully!'}), 201

# membaca keseluruhan data user
@app.route('/api/users', methods=['GET'])
@jwt_required()
def read_users():
    users = User.query.all()
    user_list = [{'id': user.id, 'username': user.username, 'fullname': user.fullname, 'status': user.status} for user in users]
    return jsonify(user_list), 200

# mengupdate user
@app.route('/api/users/<int:user_id>', methods=['PUT'])
@jwt_required()
def update_user(user_id):
    current_user = get_jwt_identity()
    if not current_user or not current_user['is_admin']:
        abort(403, description="Not authorized to update users")

    data = request.get_json()
    user = User.query.get_or_404(user_id)
    if 'username' in data:
        user.username = data['username']
    if 'password' in data:
        user.password = generate_password_hash(data['password'], method='pbkdf2:sha256')
    if 'fullname' in data:
        user.fullname = data['fullname']
    if 'status' in data:
        user.status = data['status']
    db.session.commit()
    log_activity(current_user['user_id'], 'UPDATE_USER', f"Updated user {user.username}")
    return jsonify({'message': 'User updated successfully!'}), 200

# menghapus user
@app.route('/api/users/<int:user_id>', methods=['DELETE'])
@jwt_required()
def delete_user(user_id):
    current_user = get_jwt_identity()
    if not current_user or not current_user['is_admin']:
        abort(403, description="Not authorized to delete users")

    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    log_activity(current_user['user_id'], 'DELETE_USER', f"Deleted user {user.username}")
    return jsonify({'message': 'User deleted successfully!'}), 200

# mencari user
@app.route('/api/users/search', methods=['GET'])
@jwt_required()
def search_user():
    username = request.args.get('username')
    fullname = request.args.get('fullname')
    query = User.query
    if username:
        query = query.filter(User.username.like(f"%{username}%"))
    if fullname:
        query = query.filter(User.fullname.like(f"%{fullname}%"))
    users = query.all()
    user_list = [{'id': user.id, 'username': user.username, 'fullname': user.fullname, 'status': user.status} for user in users]
    return jsonify(user_list), 200


# bagian user_group
# membuatgroup
@app.route('/api/usergroups', methods=['POST'])
@jwt_required()
def create_user_group():
    current_user = get_jwt_identity()
    if not current_user or not current_user['is_admin']:
        abort(403, description="Not authorized to create user groups")

    data = request.get_json()
    if not data or not 'name' in data or not 'description' in data:
        abort(400, description="Name and description are required")
    
    new_group = UserGroup(name=data['name'], description=data['description'])
    db.session.add(new_group)
    db.session.commit()
    return jsonify({'message': 'User group created successfully!'}), 201

# melihat keseluruhan data group
@app.route('/api/usergroups', methods=['GET'])
@jwt_required()
def read_user_groups():
    groups = UserGroup.query.all()
    group_list = [{'id': group.id, 'name': group.name, 'description': group.description} for group in groups]
    return jsonify(group_list), 200

# mengupdate group
@app.route('/api/usergroups/<int:group_id>', methods=['PUT'])
@jwt_required()
def update_user_group(group_id):
    current_user = get_jwt_identity()
    if not current_user or not current_user['is_admin']:
        abort(403, description="Not authorized to update user groups")

    data = request.get_json()
    group = UserGroup.query.get_or_404(group_id)
    if 'name' in data:
        group.name = data['name']
    if 'description' in data:
        group.description = data['description']
    db.session.commit()
    return jsonify({'message': 'User group updated successfully!'}), 200

# menghapus group
@app.route('/api/usergroups/<int:group_id>', methods=['DELETE'])
@jwt_required()
def delete_user_group(group_id):
    current_user = get_jwt_identity()
    if not current_user or not current_user['is_admin']:
        abort(403, description="Not authorized to delete user groups")

    group = UserGroup.query.get_or_404(group_id)
    db.session.delete(group)
    db.session.commit()
    return jsonify({'message': 'User group deleted successfully!'}), 200

# menambahkan user ke group
@app.route('/api/usergroups/<int:group_id>/users', methods=['POST'])
@jwt_required()
def add_user_to_group(group_id):
    current_user = get_jwt_identity()
    if not current_user or not current_user['is_admin']:
        abort(403, description="Not authorized to manage users in groups")

    data = request.get_json()
    if not data or not 'user_id' in data:
        abort(400, description="User ID is required")
    
    user_id = data['user_id']
    new_membership = UserGroupMembership(user_id=user_id, group_id=group_id)
    db.session.add(new_membership)
    db.session.commit()
    return jsonify({'message': 'User added to group successfully!'}), 201

# melihat semua aktifitas user
@app.route('/api/activitylogs', methods=['GET'])
@jwt_required()
def monitor_user_actions():
    current_user = get_jwt_identity()
    if not current_user or not current_user['is_admin']:
        abort(403, description="Not authorized to monitor user actions")

    logs = ActivityLog.query.all()
    log_list = [{'id': log.id, 'user_id': log.user_id, 'activity_type': log.activity_type, 'details': log.details, 'timestamp': log.timestamp} for log in logs]
    return jsonify(log_list), 200

# untuk membuat akun admin
@app.route('/api/admin/create', methods=['POST'])
@jwt_required()
def create_admin():
    current_user = get_jwt_identity()
    if not current_user or not current_user['is_admin']:
        abort(403, description="Not authorized to create admin")

    data = request.get_json()
    if not data or not 'username' in data or not 'password' in data:
        abort(400, description="Username and password are required")
    
    existing_user = User.query.filter_by(username=data['username']).first()
    if existing_user:
        abort(400, description="Username already exists")
    
    hashed_password = generate_password_hash(data['password'], method='pbkdf2:sha256')
    new_admin = User(username=data['username'], password=hashed_password, fullname=data.get('fullname', ''), is_admin=True)
    db.session.add(new_admin)
    db.session.commit()
    log_activity(current_user['user_id'], 'CREATE_ADMIN', f"Created admin {new_admin.username}")
    return jsonify({'message': 'Admin created successfully!'}), 201

if __name__ == '__main__':
    app.run(debug=True)
