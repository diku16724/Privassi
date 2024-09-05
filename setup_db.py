from app import db, app, User  # Import the db and app from your Flask application
from flask_migrate import Migrate
# Create the application context before doing anything with the database

# Initialize Flask-Migrate
migrate = Migrate(app, db)

with app.app_context():
    db.create_all()  # This will create the database tables
    print("Database tables created successfully!")
