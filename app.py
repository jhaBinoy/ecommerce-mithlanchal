import os
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import razorpay
from dotenv import load_dotenv

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-change-this'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////tmp/store.db'  # Render-compatible path
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
db = SQLAlchemy(app)

load_dotenv()
razorpay_client = razorpay.Client(auth=(os.getenv('RAZORPAY_KEY', ''), os.getenv('RAZORPAY_SECRET', '')))

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Float, nullable=False)
    description = db.Column(db.Text)
    image = db.Column(db.String(200))

class CartItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    quantity = db.Column(db.Integer, default=1)
    user = db.relationship('User', backref='cart_items')
    product = db.relationship('Product')

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# Initialize database and admin user
with app.app_context():
    try:
        db.create_all()
        # Add admin user if not exists
        if not User.query.filter_by(email='admin@themithlanchal.com').first():
            admin = User(
                email='admin@themithlanchal.com',
                password=generate_password_hash('admin123'),
                is_admin=True
            )
            db.session.add(admin)
            db.session.commit()
            app.logger.info("Admin user 'admin@themithlanchal.com' created")
        app.logger.info("Database tables created successfully")
    except Exception as e:
        app.logger.error(f"Failed to initialize database or admin: {e}")

@app.route('/')
def index():
    products = Product.query.all()
    return render_template('index.html', products=products)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('index'))
        flash('Invalid email or password')
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        if User.query.filter_by(email=email).first():
            flash('Email already registered')
        else:
            user = User(email=email, password=generate_password_hash(password), is_admin=False)
            db.session.add(user)
            db.session.commit()
            login_user(user)
            return redirect(url_for('index'))
    return render_template('signup.html')

@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin():
    if not current_user.is_admin:
        return redirect(url_for('index'))
    if request.method == 'POST':
        name = request.form['name']
        price = float(request.form['price'])
        description = request.form['description']
        image = request.files['image']
        filename = None
        if image:
            filename = os.path.join(app.config['UPLOAD_FOLDER'], image.filename)
            image.save(filename)
        product = Product(name=name, price=price, description=description, image=filename)
        db.session.add(product)
        db.session.commit()
        return redirect(url_for('admin'))
    products = Product.query.all()
    return render_template('admin.html', products=products)

@app.route('/product/<int:id>')
def product(id):
    product = Product.query.get_or_404(id)
    return render_template('product.html', product=product)

@app.route('/cart', methods=['GET', 'POST'])
@login_required
def cart():
    if request.method == 'POST':
        product_id = request.form.get('product_id')
        quantity = int(request.form.get('quantity', 1))
        cart_item = CartItem.query.filter_by(user_id=current_user.id, product_id=product_id).first()
        if cart_item:
            cart_item.quantity += quantity
        else:
            cart_item = CartItem(user_id=current_user.id, product_id=product_id, quantity=quantity)
            db.session.add(cart_item)
        db.session.commit()
        flash('Item added to cart')
        return redirect(url_for('cart'))
    cart_items = CartItem.query.filter_by(user_id=current_user.id).all()
    total = sum(item.product.price * item.quantity for item in cart_items)
    return render_template('cart.html', cart_items=cart_items, total=total)

@app.route('/checkout', methods=['GET', 'POST'])
@login_required
def checkout():
    cart_items = CartItem.query.filter_by(user_id=current_user.id).all()
    if not cart_items:
        flash('Your cart is empty')
        return redirect(url_for('cart'))
    total = sum(item.product.price * item.quantity for item in cart_items) * 100  # Razorpay uses paise
    order_data = {
        'amount': int(total),
        'currency': 'INR',
        'receipt': f'order_{current_user.id}',
        'payment_capture': 1
    }
    try:
        order = razorpay_client.order.create(data=order_data)
        return render_template('checkout.html', order=order, cart_items=cart_items, total=total/100,
                             razorpay_key=os.getenv('RAZORPAY_KEY'))
    except Exception as e:
        flash(f'Error creating order: {str(e)}')
        return redirect(url_for('cart'))

@app.route('/payment/success', methods=['POST'])
@login_required
def payment_success():
    payment_id = request.form.get('razorpay_payment_id')
    order_id = request.form.get('razorpay_order_id')
    signature = request.form.get('razorpay_signature')
    params_dict = {
        'razorpay_order_id': order_id,
        'razorpay_payment_id': payment_id,
        'razorpay_signature': signature
    }
    try:
        razorpay_client.utility.verify_payment_signature(params_dict)
        # Clear cart
        CartItem.query.filter_by(user_id=current_user.id).delete()
        db.session.commit()
        flash('Payment successful! Your order has been placed.')
        return redirect(url_for('index'))
    except Exception as e:
        flash(f'Payment verification failed: {str(e)}')
        return redirect(url_for('checkout'))

@app.route('/cart/remove/<int:cart_item_id>', methods=['POST'])
@login_required
def remove_from_cart(cart_item_id):
    cart_item = CartItem.query.get_or_404(cart_item_id)
    if cart_item.user_id != current_user.id:
        flash('Unauthorized action')
        return redirect(url_for('cart'))
    db.session.delete(cart_item)
    db.session.commit()
    flash('Item removed from cart')
    return redirect(url_for('cart'))

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    total = db.Column(db.Float, nullable=False)
    payment_id = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', backref='orders')

@app.route('/search')
def search():
    query = request.args.get('q')
    products = Product.query.filter(Product.name.ilike(f'%{query}%')).all()
    return render_template('index.html', products=products)

@app.route('/cart/remove/<int:cart_item_id>', methods=['POST'])
@login_required
def remove_from_cart(cart_item_id):
    cart_item = CartItem.query.get_or_404(cart_item_id)
    if cart_item.user_id != current_user.id:
        flash('Unauthorized action')
        return redirect(url_for('cart'))
    db.session.delete(cart_item)
    db.session.commit()
    flash('Item removed from cart')
    return redirect(url_for('cart'))


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)