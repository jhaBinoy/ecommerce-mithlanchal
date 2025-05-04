import os
import uuid
import re
from flask import Flask, render_template, request, redirect, url_for, flash, Response, jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_mail import Mail, Message
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from wtforms import StringField, PasswordField, SelectField, SubmitField, TextAreaField, FloatField, IntegerField
from wtforms.validators import DataRequired, Email, Length, NumberRange
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from markupsafe import escape
from PIL import Image
from datetime import datetime
from dotenv import load_dotenv
import razorpay
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from io import BytesIO
from db import db  # Import db from db.py
from flask import Flask
from flask_wtf import CSRFProtect
from sqlalchemy.orm import joinedload

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', os.urandom(24).hex())
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'postgresql://admin:gv64uAaltfP9OVOVvlNtt6dnC31PXqZR@dpg-d01bdjre5dus73e3bptg-a.oregon-postgres.render.com/store_lt18?sslmode=require')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME', 'your-email@gmail.com')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD', 'your-app-password')
app.config['MAIL_DEFAULT_SENDER'] = 'The Mithlanchal <your-email@gmail.com>'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Initialize extensions
db.init_app(app)  # Initialize db with Flask app
mail = Mail(app)
csrf = CSRFProtect(app)

load_dotenv()
razorpay_client = razorpay.Client(auth=(os.getenv('RAZORPAY_KEY', ''), os.getenv('RAZORPAY_SECRET', '')))

# Import models after db initialization to avoid circular imports
from models import User, Product, DiscountCode, CartItem, Order, OrderItem

# Cart Update Form
class CartUpdateForm(FlaskForm):
    product_id = IntegerField('Product ID', validators=[DataRequired()], render_kw={'type': 'hidden'})
    quantity = IntegerField('Quantity', validators=[DataRequired(), NumberRange(min=1)], render_kw={'aria-label': 'Quantity'})
    submit = SubmitField('Update Cart')

# Cart Form for Add to Cart
class CartForm(FlaskForm):
    product_id = IntegerField('Product ID', validators=[DataRequired()], render_kw={'type': 'hidden'})
    quantity = IntegerField('Quantity', validators=[DataRequired(), NumberRange(min=1)], default=1, render_kw={'aria-label': 'Quantity'})
    submit = SubmitField('Add to Cart')

# Add Product Form
class AddProductForm(FlaskForm):
    name = StringField('Product Name', validators=[DataRequired()], render_kw={'aria-label': 'Product name'})
    price = FloatField('Price', validators=[DataRequired(), NumberRange(min=0.01)], render_kw={'aria-label': 'Price'})
    description = TextAreaField('Description', render_kw={'aria-label': 'Description'})
    category = SelectField('Category', choices=[('puja', 'Puja Items'), ('saree', 'Sarees'), ('other', 'Other')], render_kw={'aria-label': 'Category'})
    submit = SubmitField('Add Product')

# Signup Form
class SignupForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()], render_kw={'aria-label': 'Email address'})
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)], render_kw={'aria-label': 'Password'})
    country_code = SelectField('Country Code', choices=[('+91', 'India (+91)'), ('+1', 'USA (+1)'), ('+44', 'UK (+44)'), ('+61', 'Australia (+61)')], default='+91', render_kw={'aria-label': 'Country code'})
    mobile_number = StringField('Mobile Number', validators=[Length(min=7, max=12)], render_kw={'aria-label': 'Mobile number', 'pattern': '[0-9]{7,12}', 'title': 'Enter 7-12 digits'})
    submit = SubmitField('Sign Up')

# Login Form
class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()], render_kw={'aria-label': 'Email address'})
    password = PasswordField('Password', validators=[DataRequired()], render_kw={'aria-label': 'Password'})
    submit = SubmitField('Login')

# Checkout Form
class CheckoutForm(FlaskForm):
    shipping_address = TextAreaField('Shipping Address', validators=[DataRequired()], render_kw={'aria-label': 'Shipping address'})
    mobile_number = StringField('Mobile Number', validators=[DataRequired(), Length(min=7, max=12)], render_kw={'aria-label': 'Mobile number', 'pattern': '[0-9]{7,12}', 'title': 'Enter 7-12 digits'})
    email = StringField('Email', validators=[DataRequired(), Email()], render_kw={'aria-label': 'Email address'})
    discount_code = StringField('Discount Code (Optional)', render_kw={'aria-label': 'Discount code'})
    payment_method = SelectField('Payment Method', choices=[('cod', 'Cash on Delivery'), ('razorpay', 'Online Payment (Razorpay)')], validators=[DataRequired()], render_kw={'aria-label': 'Payment method'})
    submit = SubmitField('Place Order')

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    with app.app_context():
        return db.session.get(User, int(user_id))

# HTTPS Redirect (disabled in production since Render handles HTTPS)
@app.before_request
def require_https():
    if not app.debug and not request.is_secure and not os.getenv('RENDER'):
        return redirect(request.url.replace('http://', 'https://'))

# Function to initialize the database and admin user
def init_db():
    with app.app_context():
        try:
            db.create_all()
            if not db.session.query(User).filter_by(email='admin@themithlanchal.com').first():
                admin = User(email='admin@themithlanchal.com', 
                             password=generate_password_hash('admin123'),
                             is_admin=True, mobile_number='+919876543210')
                db.session.add(admin)
                db.session.commit()
                app.logger.info("Admin user 'admin@themithlanchal.com' created")
            app.logger.info("Database tables created successfully")
        except Exception as e:
            app.logger.error(f"Failed to initialize database or admin: {e}")
            raise

# Call the initialization function
init_db()

@app.route('/')
def index():
    with app.app_context():
        query = request.args.get('query', '')
        category = request.args.get('category', '')
        min_price = request.args.get('min_price', type=float)
        max_price = request.args.get('max_price', type=float)
        products_query = Product.query
        if query:
            products_query = products_query.filter(Product.name.ilike(f'%{escape(query)}%') | Product.description.ilike(f'%{escape(query)}%'))
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
    form = LoginForm()
    if request.method == 'POST':
        if form.validate_on_submit():
            email = escape(form.email.data)
            password = form.password.data
            with app.app_context():
                user = db.session.query(User).filter_by(email=email).first()
                if user and check_password_hash(user.password, password):
                    login_user(user)
                    next_page = request.form.get('next') or request.args.get('next', url_for('index'))
                    return redirect(next_page)
                else:
                    flash('Invalid email or password')
        else:
            flash('Form validation failed. Please check your input.')
            app.logger.debug(f"Login form errors: {form.errors}")
    return render_template('login.html', form=form)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignupForm()
    if request.method == 'POST':
        if form.validate_on_submit():
            email = escape(form.email.data)
            password = form.password.data
            country_code = form.country_code.data
            mobile_number = escape(form.mobile_number.data)
            full_mobile = f"{country_code}{mobile_number}" if mobile_number and country_code else None
            with app.app_context():
                if db.session.query(User).filter_by(email=email).first():
                    flash('Email already registered')
                elif full_mobile and not re.match(r'\+[0-9]{10,15}', full_mobile):
                    flash('Invalid mobile number format')
                elif full_mobile and db.session.query(User).filter_by(mobile_number=full_mobile).first():
                    flash('Mobile number already registered')
                else:
                    user = User(
                        email=email,
                        password=generate_password_hash(password),
                        is_admin=False,
                        mobile_number=full_mobile
                    )
                    db.session.add(user)
                    db.session.commit()
                    login_user(user)
                    return redirect(url_for('index'))
        else:
            flash('Form validation failed. Please check your input.')
            app.logger.debug(f"Signup form errors: {form.errors}")
    return render_template('signup.html', form=form)

@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin():
    if not current_user.is_admin:
        return redirect(url_for('index'))
    form = AddProductForm()
    if request.method == 'POST':
        if form.validate_on_submit():
            name = escape(form.name.data)
            price = form.price.data
            description = escape(form.description.data)
            category = form.category.data
            image = request.files.get('image')
            filename = None
            if image and image.filename:
                ext = os.path.splitext(secure_filename(image.filename))[1]
                filename = f"{uuid.uuid4().hex}{ext}"
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                img = Image.open(image)
                img.thumbnail((800, 800))
                img.save(filepath, quality=85)
                filename = os.path.join('uploads', filename)
            with app.app_context():
                product = Product(name=name, price=price, description=description, image=filename, category=category)
                db.session.add(product)
                db.session.commit()
            flash('Product added successfully')
            return redirect(url_for('admin'))
        else:
            flash('Form validation failed. Please check your input.')
            app.logger.debug(f"Add product form errors: {form.errors}")
    with app.app_context():
        products = db.session.query(Product).all()
    return render_template('admin.html', products=products, form=form)

@app.route('/admin/discounts', methods=['GET', 'POST'])
@login_required
def admin_discounts():
    if not current_user.is_admin:
        return redirect(url_for('index'))
    if request.method == 'POST':
        code = escape(request.form['code']).upper()
        percentage = float(request.form['percentage'])
        expiry_str = request.form['expiry']
        expiry = datetime.strptime(expiry_str, '%Y-%m-%d')
        with app.app_context():
            if db.session.query(DiscountCode).filter_by(code=code).first():
                flash('Discount code already exists')
            else:
                discount = DiscountCode(code=code, percentage=percentage, expiry=expiry)
                db.session.add(discount)
                db.session.commit()
                flash('Discount code added')
        return redirect(url_for('admin_discounts'))
    with app.app_context():
        discounts = db.session.query(DiscountCode).all()
    return render_template('admin_discounts.html', discounts=discounts)

@app.route('/product/<int:id>')
def product(id):
    with app.app_context():
        product = db.session.query(Product).get_or_404(id)
    form = CartForm(product_id=id)
    return render_template('product.html', product=product, form=form)

@app.route('/cart', methods=['GET', 'POST'])
@login_required
def cart():
    form = CartUpdateForm()
    if request.method == 'POST':
        # Handle "Add to Cart" form submission (from product.html)
        add_to_cart_form = CartForm(request.form)
        if add_to_cart_form.validate_on_submit():
            product_id = add_to_cart_form.product_id.data
            quantity = add_to_cart_form.quantity.data
            with app.app_context():
                cart_item = db.session.query(CartItem).filter_by(user_id=current_user.id, product_id=product_id).first()
                if cart_item:
                    cart_item.quantity += quantity
                else:
                    cart_item = CartItem(user_id=current_user.id, product_id=product_id, quantity=quantity)
                    db.session.add(cart_item)
                db.session.commit()
            flash('Item added to cart successfully')
            return redirect(url_for('cart'))
        # Handle "Update Cart" form submission (from cart.html)
        if form.validate_on_submit():
            product_id = form.product_id.data
            quantity = form.quantity.data
            with app.app_context():
                cart_item = db.session.query(CartItem).filter_by(user_id=current_user.id, product_id=product_id).first()
                if cart_item:
                    cart_item.quantity = quantity
                else:
                    cart_item = CartItem(user_id=current_user.id, product_id=product_id, quantity=quantity)
                    db.session.add(cart_item)
                db.session.commit()
            flash('Cart updated successfully')
            return redirect(url_for('cart'))
        # If neither form validates, flash the appropriate error
        if add_to_cart_form.errors:
            flash('Add to cart failed. Please check your input.')
            app.logger.debug(f"Add to cart form errors: {add_to_cart_form.errors}")
        if form.errors:
            flash('Cart update failed. Please check your input.')
            app.logger.debug(f"Update cart form errors: {form.errors}")
        return redirect(url_for('cart'))
    with app.app_context():
        cart_items = db.session.query(CartItem).filter_by(user_id=current_user.id).all()
        total = round(sum(item.product.price * item.quantity for item in cart_items), 2)
    return render_template('cart.html', cart_items=cart_items, total=total, form=form)

@app.route('/cart/remove/<int:cart_item_id>', methods=['POST'])
@login_required
def remove_from_cart(cart_item_id):
    with app.app_context():
        cart_item = db.session.query(CartItem).get_or_404(cart_item_id)
        if cart_item.user_id != current_user.id:
            flash('Unauthorized action')
            return redirect(url_for('cart'))
        db.session.delete(cart_item)
        db.session.commit()
    flash('Item removed from cart')
    return redirect(url_for('cart'))

@app.route('/cart/increase/<int:cart_item_id>', methods=['POST'])
@login_required
def increase_cart_item(cart_item_id):
    with app.app_context():
        cart_item = db.session.query(CartItem).get_or_404(cart_item_id)
        if cart_item.user_id != current_user.id:
            return jsonify({'error': 'Unauthorized action'}), 403
        cart_item.quantity += 1
        db.session.commit()
        total = round(sum(item.product.price * item.quantity for item in db.session.query(CartItem).filter_by(user_id=current_user.id).all()), 2)
    return jsonify({
        'success': True,
        'message': 'Quantity increased',
        'quantity': cart_item.quantity,
        'item_total': round(cart_item.product.price * cart_item.quantity, 2),
        'cart_total': total
    })

@app.route('/cart/decrease/<int:cart_item_id>', methods=['POST'])
@login_required
def decrease_cart_item(cart_item_id):
    with app.app_context():
        cart_item = db.session.query(CartItem).get_or_404(cart_item_id)
        if cart_item.user_id != current_user.id:
            return jsonify({'error': 'Unauthorized action'}), 403
        if cart_item.quantity > 1:
            cart_item.quantity -= 1
            db.session.commit()
            total = round(sum(item.product.price * item.quantity for item in db.session.query(CartItem).filter_by(user_id=current_user.id).all()), 2)
            return jsonify({
                'success': True,
                'message': 'Quantity decreased',
                'quantity': cart_item.quantity,
                'item_total': round(cart_item.product.price * cart_item.quantity, 2),
                'cart_total': total
            })
        else:
            db.session.delete(cart_item)
            db.session.commit()
            total = round(sum(item.product.price * item.quantity for item in db.session.query(CartItem).filter_by(user_id=current_user.id).all()), 2)
            return jsonify({
                'success': True,
                'message': 'Item removed from cart',
                'quantity': 0,
                'item_total': 0,
                'cart_total': total
            })

@app.route('/checkout', methods=['GET', 'POST'])
@login_required
def checkout():
    form = CheckoutForm()
    with app.app_context():
        cart_items = db.session.query(CartItem).filter_by(user_id=current_user.id).all()
        if not cart_items:
            flash('Your cart is empty')
            return redirect(url_for('cart'))
        total = round(sum(item.product.price * item.quantity for item in cart_items), 2)
        discount = 0.0
        discount_code = None
        if request.method == 'POST':
            if form.validate_on_submit():
                shipping_address = escape(form.shipping_address.data)
                mobile_number = escape(form.mobile_number.data)
                email = escape(form.email.data)
                payment_method = form.payment_method.data
                discount_code_str = escape(form.discount_code.data).upper()
                if discount_code_str:
                    discount_code = db.session.query(DiscountCode).filter_by(
                        code=discount_code_str, active=True
                    ).filter(DiscountCode.expiry >= datetime.utcnow()).first()
                    if discount_code:
                        discount = round(total * (discount_code.percentage / 100), 2)
                        total = round(total - discount, 2)
                    else:
                        flash('Invalid or expired discount code')
                        return render_template('checkout.html', cart_items=cart_items, total=total, discount=discount, form=form, user_email=current_user.email)
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
                                             form=form, user_email=current_user.email)
                    except Exception as e:
                        flash(f'Error creating Razorpay order: {str(e)}')
                        db.session.delete(order)
                        db.session.commit()
                        return redirect(url_for('cart'))
                elif payment_method == 'cod':
                    db.session.query(CartItem).filter_by(user_id=current_user.id).delete()
                    db.session.commit()
                    try:
                        items_list = ''
                        for item in order.order_items:
                            items_list += f'- {item.product.name} (x{item.quantity}): ₹{item.price * item.quantity:.2f}\n'
                        msg = Message(
                            subject=f"The Mithlanchal - Order #{order.id} Confirmed",
                            recipients=[order.email],
                            body=f"""
Dear Customer,

Thank you for your order at The Mithlanchal!

Order #{order.id}
Date: {datetime.utcnow().strftime('%Y-%m-%d %H:%M')}
Total: ₹{order.total:.2f}
{f'Discount: ₹{discount:.2f}' if discount > 0 else ''}
Payment: Cash on Delivery
Shipping: {order.shipping_address}
Mobile: {order.mobile_number}

Items:
{items_list}

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
            else:
                flash('Please fill in all required fields')
                app.logger.debug(f"Checkout form errors: {form.errors}")
    return render_template('checkout.html', cart_items=cart_items, total=total, discount=discount, form=form, user_email=current_user.email)

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
    with app.app_context():
        try:
            razorpay_client.utility.verify_payment_signature(params_dict)
            order = db.session.query(Order).get_or_404(db_order_id)
            order.payment_id = payment_id
            order.status = 'confirmed'
            db.session.query(CartItem).filter_by(user_id=current_user.id).delete()
            db.session.commit()
            try:
                items_list = ''
                for item in order.order_items:
                    items_list += f'- {item.product.name} (x{item.quantity}): ₹{item.price * item.quantity:.2f}\n'
                msg = Message(
                    subject=f"The Mithlanchal - Order #{order.id} Confirmed",
                    recipients=[order.email],
                    body=f"""
Dear Customer,

Thank you for your order at The Mithlanchal!

Order #{order.id}
Date: {datetime.utcnow().strftime('%Y-%m-%d %H:%M')}
Total: ₹{order.total:.2f}
{f'Discount: ₹{order.discount_applied:.2f}' if order.discount_applied > 0 else ''}
Payment: Online (ID: {payment_id})
Shipping: {order.shipping_address}
Mobile: {order.mobile_number}

Items:
{items_list}

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
    with app.app_context():
        order = db.session.query(Order).options(
            joinedload(Order.order_items).joinedload(OrderItem.product)
        ).get_or_404(order_id)
        if order.user_id != current_user.id:
            flash('Unauthorized access')
            return redirect(url_for('index'))
    return render_template('order_confirmation.html', order=order)

@app.route('/invoice/<int:order_id>')
@login_required
def generate_invoice(order_id):
    with app.app_context():
        order = db.session.query(Order).options(
            joinedload(Order.order_items).joinedload(OrderItem.product)
        ).get_or_404(order_id)
        if order.user_id != current_user.id:
            flash('Unauthorized access')
            return redirect(url_for('index'))
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    elements = []
    styles = getSampleStyleSheet()
    elements.append(Paragraph("The Mithlanchal - Invoice", styles['Title']))
    elements.append(Paragraph("GSTIN: 29ABCDE1234F1Z5", styles['Normal']))
    elements.append(Paragraph(f"Order #{order.id}", styles['Heading2']))
    elements.append(Paragraph(f"Date: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
    elements.append(Paragraph(f"Customer Email: {order.email}", styles['Normal']))
    elements.append(Paragraph(f"Mobile: {order.mobile_number}", styles['Normal']))
    elements.append(Paragraph(f"Shipping Address: {order.shipping_address}", styles['Normal']))
    elements.append(Spacer(1, 12))
    data = [['Product', 'Price', 'Quantity', 'Total']]
    for item in order.order_items:
        data.append([
            item.product.name,
            f"₹{item.price:.2f}",
            item.quantity,
            f"₹{item.price * item.quantity:.2f}"
        ])
    data.append(['', '', 'Subtotal', f"₹{sum(item.price * item.quantity for item in order.order_items):.2f}"])
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

@app.route('/privacy')
def privacy():
    return render_template('privacy.html')

@app.route('/terms')
def terms():
    return render_template('terms.html')

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(e):
    return render_template('500.html'), 500

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=os.getenv('FLASK_DEBUG', 'True') == 'True')