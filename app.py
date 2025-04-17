import os
from flask import Flask, render_template, request, redirect, url_for, flash, Response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
import razorpay
from datetime import datetime
from dotenv import load_dotenv
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from io import BytesIO

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-change-this'
app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{os.path.join(os.getcwd(), 'store.db')}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME', 'your-email@gmail.com')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD', 'your-app-password')
app.config['MAIL_DEFAULT_SENDER'] = 'The Mithlanchal <your-email@gmail.com>'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
db = SQLAlchemy(app)
mail = Mail(app)

load_dotenv()
razorpay_client = razorpay.Client(auth=(os.getenv('RAZORPAY_KEY', ''), os.getenv('RAZORPAY_SECRET', '')))

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    mobile_number = db.Column(db.String(15), unique=True, nullable=True)

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Float, nullable=False)
    description = db.Column(db.Text)
    image = db.Column(db.String(200))
    category = db.Column(db.String(50), nullable=True)  # e.g., 'puja', 'saree'

class CartItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    quantity = db.Column(db.Integer, default=1)
    user = db.relationship('User', backref='cart_items')
    product = db.relationship('Product')

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    total = db.Column(db.Float, nullable=False)
    payment_method = db.Column(db.String(20), nullable=False)
    payment_id = db.Column(db.String(100), nullable=True)
    status = db.Column(db.String(20), default='pending')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    shipping_address = db.Column(db.Text, nullable=False)
    mobile_number = db.Column(db.String(15), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    discount_code_id = db.Column(db.Integer, db.ForeignKey('discount_code.id'), nullable=True)
    discount_applied = db.Column(db.Float, default=0.0)
    user = db.relationship('User', backref='orders')
    items = db.relationship('OrderItem', backref='order', cascade='all, delete-orphan')
    discount_code = db.relationship('DiscountCode')

class OrderItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('order.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    price = db.Column(db.Float, nullable=False)
    product = db.relationship('Product')

class DiscountCode(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(20), unique=True, nullable=False)
    percentage = db.Column(db.Float, nullable=False)
    expiry = db.Column(db.DateTime, nullable=False)
    active = db.Column(db.Boolean, default=True)

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
    query = request.args.get('query', '')
    category = request.args.get('category', '')
    min_price = request.args.get('min_price', type=float)
    max_price = request.args.get('max_price', type=float)
    products_query = Product.query
    if query:
        products_query = products_query.filter(Product.name.ilike(f'%{query}%') | Product.description.ilike(f'%{query}%'))
    if category:
        products_query = products_query.filter(Product.category == category)
    if min_price is not None:
        products_query = products_query.filter(Product.price >= min_price)
    if max_price is not None:
        products_query = products_query.filter(Product.price <= max_price)
    products = products_query.all()
    categories = db.session.query(Product.category).distinct().all()
    categories = [c[0] for c in categories if c[0]]
    return render_template('index.html', products=products, categories=categories)

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
        category = request.form['category']
        image = request.files['image']
        filename = None
        if image:
            filename = os.path.join(app.config['UPLOAD_FOLDER'], image.filename)
            image.save(filename)
        product = Product(name=name, price=price, description=description, image=filename, category=category)
        db.session.add(product)
        db.session.commit()
        return redirect(url_for('admin'))
    products = Product.query.all()
    return render_template('admin.html', products=products)

@app.route('/admin/discounts', methods=['GET', 'POST'])
@login_required
def admin_discounts():
    if not current_user.is_admin:
        return redirect(url_for('index'))
    if request.method == 'POST':
        code = request.form['code'].upper()
        percentage = float(request.form['percentage'])
        expiry_str = request.form['expiry']
        expiry = datetime.strptime(expiry_str, '%Y-%m-%d')
        if DiscountCode.query.filter_by(code=code).first():
            flash('Discount code already exists')
        else:
            discount = DiscountCode(code=code, percentage=percentage, expiry=expiry)
            db.session.add(discount)
            db.session.commit()
            flash('Discount code added')
        return redirect(url_for('admin_discounts'))
    discounts = DiscountCode.query.all()
    return render_template('admin_discounts.html', discounts=discounts)

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

@app.route('/cart/decrease/<int:cart_item_id>', methods=['POST'])
@login_required
def decrease_cart_item(cart_item_id):
    cart_item = CartItem.query.get_or_404(cart_item_id)
    if cart_item.user_id != current_user.id:
        flash('Unauthorized action')
        return redirect(url_for('cart'))
    if cart_item.quantity > 1:
        cart_item.quantity -= 1
        db.session.commit()
        flash('Quantity decreased')
    else:
        db.session.delete(cart_item)
        db.session.commit()
        flash('Item removed from cart')
    return redirect(url_for('cart'))

@app.route('/checkout', methods=['GET', 'POST'])
@login_required
def checkout():
    cart_items = CartItem.query.filter_by(user_id=current_user.id).all()
    if not cart_items:
        flash('Your cart is empty')
        return redirect(url_for('cart'))
    total = sum(item.product.price * item.quantity for item in cart_items)
    discount = 0.0
    discount_code = None
    if request.method == 'POST':
        shipping_address = request.form.get('shipping_address')
        mobile_number = request.form.get('mobile_number')
        email = request.form.get('email')
        payment_method = request.form.get('payment_method')
        discount_code_str = request.form.get('discount_code', '').upper()

        # Basic validation
        if not all([shipping_address, mobile_number, email, payment_method]):
            flash('Please fill in all required fields')
            return render_template('checkout.html', cart_items=cart_items, total=total, discount=discount, user_email=current_user.email)
        if not (payment_method in ['razorpay', 'cod']):
            flash('Invalid payment method')
            return render_template('checkout.html', cart_items=cart_items, total=total, discount=discount, user_email=current_user.email)

        # Apply discount
        if discount_code_str:
            discount_code = DiscountCode.query.filter_by(
                code=discount_code_str, active=True
            ).filter(DiscountCode.expiry >= datetime.utcnow()).first()
            if discount_code:
                discount = total * (discount_code.percentage / 100)
                total -= discount
            else:
                flash('Invalid or expired discount code')

        order = Order(
            user_id=current_user.id,
            total=total,
            payment_method=payment_method,
            status='pending',
            shipping_address=shipping_address,
            mobile_number=mobile_number,
            email=email,
            discount_code_id=discount_code.id if discount_code else None,
            discount_applied=discount
        )
        db.session.add(order)
        for item in cart_items:
            order_item = OrderItem(
                order=order,
                product_id=item.product_id,
                quantity=item.quantity,
                price=item.product.price
            )
            db.session.add(order_item)
        db.session.commit()

        if payment_method == 'razorpay':
            order_data = {
                'amount': int(total * 100),
                'currency': 'INR',
                'receipt': f'order_{order.id}',
                'payment_capture': 1
            }
            try:
                razorpay_order = razorpay_client.order.create(data=order_data)
                return render_template('checkout.html', order=razorpay_order, cart_items=cart_items, total=total,
                                     razorpay_key=os.getenv('RAZORPAY_KEY'), db_order_id=order.id, discount=discount,
                                     user_email=current_user.email)
            except Exception as e:
                flash(f'Error creating Razorpay order: {str(e)}')
                db.session.delete(order)
                db.session.commit()
                return redirect(url_for('cart'))
        elif payment_method == 'cod':
            CartItem.query.filter_by(user_id=current_user.id).delete()
            db.session.commit()
            try:
                msg = Message(
                    subject=f"The Mithlanchal - Order #{order.id} Confirmed",
                    recipients=[order.email],
                    body=f"""
                    Dear Customer,

                    Thank you for your order at The Mithlanchal!

                    Order #{order.id}
                    Date: {order.created_at.strftime('%Y-%m-%d %H:%M')}
                    Total: ₹{order.total:.2f}
                    {'Discount: ₹%.2f' % discount if discount > 0 else ''}
                    Payment: Cash on Delivery
                    Shipping: {order.shipping_address}
                    Mobile: {order.mobile_number}

                    Items:
                    {''.join([f'- {item.product.name} (x{item.quantity}): ₹{item.price * item.quantity:.2f}\n' for item in order.items])}

                    We'll notify you when it ships!

                    Best,
                    The Mithlanchal Team
                    """
                )
                mail.send(msg)
            except Exception as e:
                app.logger.error(f"Email failed: {e}")
            flash('Order placed successfully with Cash on Delivery!')
            return redirect(url_for('order_confirmation', order_id=order.id))
    return render_template('checkout.html', cart_items=cart_items, total=total, discount=discount, user_email=current_user.email)

@app.route('/payment/success', methods=['POST'])
@login_required
def payment_success():
    payment_id = request.form.get('razorpay_payment_id')
    order_id = request.form.get('razorpay_order_id')
    signature = request.form.get('razorpay_signature')
    db_order_id = request.form.get('db_order_id')
    params_dict = {
        'razorpay_order_id': order_id,
        'razorpay_payment_id': payment_id,
        'razorpay_signature': signature
    }
    try:
        razorpay_client.utility.verify_payment_signature(params_dict)
        order = Order.query.get_or_404(db_order_id)
        order.payment_id = payment_id
        order.status = 'confirmed'
        CartItem.query.filter_by(user_id=current_user.id).delete()
        db.session.commit()
        try:
            msg = Message(
                subject=f"The Mithlanchal - Order #{order.id} Confirmed",
                recipients=[order.email],
                body=f"""
                Dear Customer,

                Thank you for your order at The Mithlanchal!

                Order #{order.id}
                Date: {order.created_at.strftime('%Y-%m-%d %H:%M')}
                Total: ₹{order.total:.2f}
                {'Discount: ₹%.2f' % order.discount_applied if order.discount_applied > 0 else ''}
                Payment: Online (ID: {payment_id})
                Shipping: {order.shipping_address}
                Mobile: {order.mobile_number}

                Items:
                {''.join([f'- {item.product.name} (x{item.quantity}): ₹{item.price * item.quantity:.2f}\n' for item in order.items])}

                We'll notify you when it ships!

                Best,
                The Mithlanchal Team
                """
            )
            mail.send(msg)
        except Exception as e:
            app.logger.error(f"Email failed: {e}")
        flash('Payment successful! Your order is confirmed.')
        return redirect(url_for('order_confirmation', order_id=order.id))
    except Exception as e:
        flash(f'Payment verification failed: {str(e)}')
        return redirect(url_for('checkout'))

@app.route('/order/<int:order_id>')
@login_required
def order_confirmation(order_id):
    order = Order.query.get_or_404(order_id)
    if order.user_id != current_user.id:
        flash('Unauthorized access')
        return redirect(url_for('index'))
    return render_template('order_confirmation.html', order=order)

@app.route('/invoice/<int:order_id>')
@login_required
def generate_invoice(order_id):
    order = Order.query.get_or_404(order_id)
    if order.user_id != current_user.id:
        flash('Unauthorized access')
        return redirect(url_for('index'))

    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    elements = []
    styles = getSampleStyleSheet()

    elements.append(Paragraph("The Mithlanchal - Invoice", styles['Title']))
    elements.append(Paragraph(f"Order #{order.id}", styles['Heading2']))
    elements.append(Paragraph(f"Date: {order.created_at.strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
    elements.append(Paragraph(f"Customer Email: {order.email}", styles['Normal']))
    elements.append(Paragraph(f"Mobile: {order.mobile_number}", styles['Normal']))
    elements.append(Paragraph(f"Shipping Address: {order.shipping_address}", styles['Normal']))
    elements.append(Spacer(1, 12))

    data = [['Product', 'Price', 'Quantity', 'Total']]
    for item in order.items:
        data.append([
            item.product.name,
            f"₹{item.price:.2f}",
            item.quantity,
            f"₹{item.price * item.quantity:.2f}"
        ])
    data.append(['', '', 'Subtotal', f"₹{sum(item.price * item.quantity for item in order.items):.2f}"])
    if order.discount_applied > 0:
        data.append(['', '', 'Discount', f"-₹{order.discount_applied:.2f}"])
    data.append(['', '', 'Total', f"₹{order.total:.2f}"])
    table = Table(data)
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 14),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    elements.append(table)
    elements.append(Spacer(1, 12))

    elements.append(Paragraph(f"Payment Method: {order.payment_method.title()}", styles['Normal']))
    if order.payment_id:
        elements.append(Paragraph(f"Payment ID: {order.payment_id}", styles['Normal']))
    elements.append(Paragraph("Thank you for shopping with The Mithlanchal!", styles['Normal']))

    doc.build(elements)
    buffer.seek(0)
    return Response(
        buffer,
        mimetype='application/pdf',
        headers={'Content-Disposition': f'attachment;filename=invoice_{order.id}.pdf'}
    )

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)