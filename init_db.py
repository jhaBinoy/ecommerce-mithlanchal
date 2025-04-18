
from app import app, db
from app import User
from werkzeug.security import generate_password_hash

def init_db():
    with app.app_context():
        # Drop all tables and recreate them
        db.drop_all()
        db.create_all()
        
        # Create admin user if not exists
        if not User.query.filter_by(email='admin@themithlanchal.com').first():
            admin = User(
                email='admin@themithlanchal.com',
                password=generate_password_hash('admin123'),
                is_admin=True,
                mobile_number=None
            )
            db.session.add(admin)
            db.session.commit()
            print("Admin user 'admin@themithlanchal.com' created")
        
        print("Database initialized successfully")

if __name__ == '__main__':
    init_db()