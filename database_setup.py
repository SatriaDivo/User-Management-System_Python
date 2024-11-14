# database_setup.py

from models import db, User
from werkzeug.security import generate_password_hash
from app import app

with app.app_context():
    db.drop_all()
    db.create_all()

    if not User.query.filter_by(username='admin').first():
        admin = User(
            username='admin',
            password=generate_password_hash('admin', method='pbkdf2:sha256'),
            fullname='Administrator',
            is_admin=True
        )
        db.session.add(admin)
        db.session.commit()
        print("Admin user created with username 'admin' and password 'admin'.")

    print("Database setup completed.")
