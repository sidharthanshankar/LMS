import os
from dotenv import load_dotenv

# Find the .env file in the root folder
basedir = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(basedir, '..', '.env')) # '..' because config.py is inside /controller/

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'expo_secret_key_2026'
    
    # DB Path
    SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(basedir, '..', 'library.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Email Settings
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = 'sidhusankar10@gmail.com'
    
    # This pulls from the .env file safely
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    MAIL_DEFAULT_SENDER = 'sidhusankar10@gmail.com'