import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'f6138b2251231a2e9f7059b29dbe0d4d94fca82f62b393360c5e61a40588c6aa'
    SQLALCHEMY_DATABASE_URI = 'sqlite:///ids.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
