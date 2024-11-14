import os

class Config:
    SECRET_KEY = 'networkprogramming'
    BASEDIR = os.path.dirname(os.path.abspath(__file__))
    DB_FOLDER = r'D:\Tugas Kuliah\Semester 2\Pemrograman Jaringan I\User Management System - 2'
    SQLALCHEMY_DATABASE_URI = f'sqlite:///{os.path.join(DB_FOLDER, "user_management.db")}'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
