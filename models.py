from db import db  # Import db from db.py

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    mobile_number = db.Column(db.String(15))
    cart_items = db.relationship('CartItem', backref='user', lazy=True)
    orders = db.relationship('Order', backref='user', lazy=True)

    # Flask-Login required properties
    @property
    def is_active(self):
        # Add logic here if you have a way to deactivate users (e.g., a 'banned' column)
        return True  # For now, assume all users are active

    @property
    def is_authenticated(self):
        return True  # Users are authenticated if they are logged in

    @property
    def is_anonymous(self):
        return False  # This is a logged-in user, not anonymous

    def get_id(self):
        return str(self.id)  # Return the user ID as a string for Flask-Login

class Product(db.Model):
    __tablename__ = 'products'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Float, nullable=False)
    description = db.Column(db.Text)
    image = db.Column(db.String(255))
    category = db.Column(db.String(50))
    cart_items = db.relationship('CartItem', backref='product', lazy=True)
    order_items = db.relationship('OrderItem', backref='product', lazy=True)

class DiscountCode(db.Model):
    __tablename__ = 'discount_codes'
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(20), unique=True, nullable=False)
    percentage = db.Column(db.Float, nullable=False)
    expiry = db.Column(db.DateTime, nullable=False)
    active = db.Column(db.Boolean, default=True)
    orders = db.relationship('Order', backref='discount_code', lazy=True)

class CartItem(db.Model):
    __tablename__ = 'cart_items'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('products.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)

class Order(db.Model):
    __tablename__ = 'orders'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    total = db.Column(db.Float, nullable=False)
    payment_method = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(50), nullable=False, default='pending')  # Supports 'pending', 'processing', 'shipped', 'delivered', 'cancelled'
    shipping_address = db.Column(db.Text, nullable=False)
    mobile_number = db.Column(db.String(20), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    payment_id = db.Column(db.String(100), nullable=True)
    discount_code_id = db.Column(db.Integer, db.ForeignKey('discount_codes.id'), nullable=True)
    discount_applied = db.Column(db.Float, default=0.0)
    created_at = db.Column(db.DateTime, nullable=False, default=db.func.current_timestamp())
    order_items = db.relationship('OrderItem', backref='order', lazy=True)

class OrderItem(db.Model):
    __tablename__ = 'order_items'
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('orders.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('products.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    price = db.Column(db.Float, nullable=False)