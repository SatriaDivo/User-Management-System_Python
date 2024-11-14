Langkah 1: Persiapkan Virtual Environment
1. Buat Virtual Environment agar tidak mengganggu dependensi Python lainnya:
   python -m venv venv

2. Aktifkan Virtual Environment:
   Di Windows:
   venv\Scripts\activate

   Di MacOS/Linux:
   source venv/bin/activate

Langkah 2: Instal Flask dan Dependensi Lainnya
1. Instal Flask dan modul tambahan yang dibutuhkan, seperti flask_sqlalchemy, flask_jwt_extended, dan werkzeug:
   pip install Flask Flask-JWT-Extended Flask-SQLAlchemy Werkzeug

2. Jika aplikasi memerlukan konfigurasi spesifik, buat file bernama config.py untuk menyimpan konfigurasi aplikasi, seperti JWT_SECRET_KEY dan pengaturan database.


Langkah 3: Siapkan File Model dan Database
1. Buat file models.py yang berisi model database Anda (User, UserGroup, UserGroupMembership, ActivityLog) dengan SQLAlchemy.
   
2. Pastikan Anda menginisialisasi database di aplikasi Flask menggunakan SQLAlchemy.
   Code berapa di file models.py

Langkah 4: Inisialisasi Database
1. Buat tabel-tabel database dengan perintah:
   from app import db, app
with app.app_context():
    db.create_all()
   
Code berapa di file database_setup.py

Langkah 5: Menjalankan Aplikasi
1. Jalankan aplikasi Flask dengan perintah:
   flask run
