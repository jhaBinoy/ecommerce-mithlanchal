from extensions import db
from datetime import datetime
from flask_login import UserMixin

class User(db.Model, UserMixin):
    __tablename__ = 'users'
    __table_args__ = {'schema': 'mithlanchal_store'}
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    mobile_number = db.Column(db.String(20))
    cart_items = db.relationship('CartItem', back_populates='user', cascade='all, delete-orphan')
    orders = db.relationship('Order', back_populates='user', cascade='all, delete-orphan')

    @property
    def is_active(self):
        return True

    @property
    def is_authenticated(self):
        return True

    @property
    def is_anonymous(self):
        return False

    def get_id(self):
        return str(self.id)

class Product(db.Model):
    __tablename__ = 'products'
    __table_args__ = {'schema': 'mithlanchal_store'}
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Float, nullable=False)
    description = db.Column(db.Text)
    category = db.Column(db.String(50))
    images = db.relationship('ProductImage', back_populates='product', cascade='all, delete-orphan')
    cart_items = db.relationship('CartItem', back_populates='product', cascade='all, delete-orphan')
    order_items = db.relationship('OrderItem', back_populates='product', cascade='all, delete-orphan')
    discount_codes = db.relationship('DiscountCode', back_populates='product')

class ProductImage(db.Model):
    __tablename__ = 'product_images'
    __table_args__ = {'schema': 'mithlanchal_store'}
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey('mithlanchal_store.products.id'), nullable=False)
    image = db.Column(db.String(255), nullable=False)
    position = db.Column(db.Integer, default=1)
    signed_url = db.Column(db.Text)
    expiration_timestamp = db.Column(db.DateTime)
    product = db.relationship('Product', back_populates='images')

class DiscountCode(db.Model):
    __tablename__ = 'discount_codes'
    __table_args__ = {'schema': 'mithlanchal_store'}
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(20), unique=True, nullable=False)
    percentage = db.Column(db.Float, nullable=False)
    expiry = db.Column(db.DateTime, nullable=False)
    active = db.Column(db.Boolean, default=True)
    product_id = db.Column(db.Integer, db.ForeignKey('mithlanchal_store.products.id'), nullable=True)
    category = db.Column(db.String(50), nullable=True)
    product = db.relationship('Product', back_populates='discount_codes')
    orders = db.relationship('Order', back_populates='discount_code')

class CartItem(db.Model):
    __tablename__ = 'cart_items'
    __table_args__ = {'schema': 'mithlanchal_store'}
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('mithlanchal_store.users.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('mithlanchal_store.products.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False, default=1)
    user = db.relationship('User', back_populates='cart_items')
    product = db.relationship('Product', back_populates='cart_items')

class Order(db.Model):
    __tablename__ = 'orders'
    __table_args__ = {'schema': 'mithlanchal_store'}
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('mithlanchal_store.users.id'), nullable=False)
    total = db.Column(db.Float, nullable=False)
    payment_method = db.Column(db.String(50), nullable=False)
    payment_id = db.Column(db.String(100))
    status = db.Column(db.String(20), default='pending')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    shipping_address = db.Column(db.Text, nullable=False)
    mobile_number = db.Column(db.String(20), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    discount_code_id = db.Column(db.Integer, db.ForeignKey('mithlanchal_store.discount_codes.id'))
    discount_applied = db.Column(db.Float, default=0.0)
    user = db.relationship('User', back_populates='orders')
    discount_code = db.relationship('DiscountCode', back_populates='orders')
    order_items = db.relationship('OrderItem', back_populates='order', cascade='all, delete-orphan')

class OrderItem(db.Model):
    __tablename__ = 'order_items'
    __table_args__ = {'schema': 'mithlanchal_store'}
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('mithlanchal_store.orders.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('mithlanchal_store.products.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    price = db.Column(db.Float, nullable=False)
    order = db.relationship('Order', back_populates='order_items')
    product = db.relationship('Product', back_populates='order_items')