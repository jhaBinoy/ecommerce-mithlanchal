from app import app, db, User

with app.app_context():
    users = [u.email for u in db.session.query(User).all()]
    print(users)