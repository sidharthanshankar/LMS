import os

class Config:
    SECRET_KEY = 'expo_secret_key_2026'
    SQLALCHEMY_DATABASE_URI = 'sqlite:///../library.db' # Stores DB in root
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Email Settings for Reminders
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = 'sidhusankar10@gmail.com' # Your email
    MAIL_PASSWORD = 'ofqe yzdi mhzj tcwn'