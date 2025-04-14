import os

class Config:
    # Flask configuration
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your-secret-key-here'
    
    # Database configuration
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///enrollment.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Flask-Admin configuration
    FLASK_ADMIN_SWATCH = 'cerulean'