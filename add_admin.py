from app import app, db, User
from werkzeug.security import generate_password_hash

with app.app_context():
    admin = User(email='admin@themithlanchal.com', password=generate_password_hash('admin123'), is_admin=True)
    db.session.add(admin)
    db.session.commit()
    print("Admin user 'admin@themithlanchal.com' added successfully")