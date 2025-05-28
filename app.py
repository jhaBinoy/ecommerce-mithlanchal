import os
import uuid
import re
from flask import Flask, render_template, request, redirect, url_for, flash, Response
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask_mail import Mail, Message
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from wtforms import StringField, PasswordField, SelectField, SubmitField, TextAreaField, FloatField, IntegerField, DateField, FileField
from wtforms.validators import DataRequired, Email, Length, NumberRange
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from markupsafe import escape
from PIL import Image
from datetime import datetime, timedelta
from dotenv import load_dotenv
import razorpay
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from io import BytesIO
from flask_migrate import Migrate
from sqlalchemy.orm import joinedload
from sqlalchemy.sql import text
from sqlalchemy import or_
import logging
from b2sdk.v2 import B2Api, InMemoryAccountInfo
from extensions import db
import urllib.parse
from functools import lru_cache

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', os.urandom(24).hex())
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'postgresql://admin:o6EsRZd9mQaSEmS6XEKH6cloIuKyrh3c@dpg-d0lo3pogjchc73f8k8l0-a.oregon-postgres.render.com/store_lt18_sykd?sslmode=require')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME', 'your-email@gmail.com')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD', 'your-app-password')
app.config['MAIL_DEFAULT_SENDER'] = 'The Mithlanchal <your-email@gmail.com>'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=1)
app.config['SESSION_COOKIE_SECURE'] = False if os.getenv('FLASK_DEBUG', 'True') == 'True' else True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

logging.basicConfig(level=logging.INFO)
app.logger.setLevel(logging.INFO)

# Initialize database
db.init_app(app)
migrate = Migrate(app, db)

# Initialize extensions
mail = Mail(app)
csrf = CSRFProtect(app)

# Backblaze B2 Configuration
load_dotenv()
B2_KEY_ID = os.getenv('B2_KEY_ID')
B2_APPLICATION_KEY = os.getenv('B2_APPLICATION_KEY')
B2_BUCKET_NAME = os.getenv('B2_BUCKET_NAME', 'mithlanchal-images')

b2_api = B2Api(InMemoryAccountInfo())
try:
    b2_api.authorize_account("production", B2_KEY_ID, B2_APPLICATION_KEY)
    app.logger.info("Backblaze B2 authorized successfully")
except Exception as e:
    app.logger.error(f"Failed to authorize Backblaze B2: {e}")
    raise Exception(f"Backblaze B2 initialization failed: {e}")

@lru_cache(maxsize=1)
def get_bucket():
    return b2_api.get_bucket_by_name(B2_BUCKET_NAME)

bucket = get_bucket()

razorpay_client = razorpay.Client(auth=(os.getenv('RAZORPAY_KEY', ''), os.getenv('RAZORPAY_SECRET', '')))

# Import models
from models import User, Product, ProductImage, DiscountCode, CartItem, Order, OrderItem

# Forms
class CSRFOnlyForm(FlaskForm):
    pass

class CartForm(FlaskForm):
    product_id = IntegerField('Product ID', validators=[DataRequired()], render_kw={'type': 'hidden'})
    quantity = IntegerField('Quantity', validators=[DataRequired(), NumberRange(min=1)], default=1, render_kw={'aria-label': 'Quantity'})
    submit = SubmitField('Add to Cart')

class AddProductForm(FlaskForm):
    name = StringField('Product Name', validators=[DataRequired()], render_kw={'aria-label': 'Product name'})
    price = FloatField('Price', validators=[DataRequired(), NumberRange(min=0.01)], render_kw={'aria-label': 'Price'})
    description = TextAreaField('Description', render_kw={'aria-label': 'Description'})
    category = SelectField('Category', choices=[('puja', 'Puja Items'), ('saree', 'Sarees'), ('other', 'Other')], render_kw={'aria-label': 'Category'})
    images = FileField('Product Images', render_kw={'multiple': True, 'accept': 'image/*', 'aria-label': 'Product images'})
    submit = SubmitField('Add Product')

class EditProductForm(FlaskForm):
    name = StringField('Product Name', validators=[DataRequired()], render_kw={'aria-label': 'Product name'})
    price = FloatField('Price', validators=[DataRequired(), NumberRange(min=0.01)], render_kw={'aria-label': 'Price'})
    description = TextAreaField('Description', render_kw={'aria-label': 'Description'})
    category = SelectField('Category', choices=[('puja', 'Puja Items'), ('saree', 'Sarees'), ('other', 'Other')], render_kw={'aria-label': 'Category'})
    images = FileField('Add New Images', render_kw={'multiple': True, 'accept': 'image/*', 'aria-label': 'Product images'})
    submit = SubmitField('Update Product')

class SignupForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()], render_kw={'aria-label': 'Email address'})
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)], render_kw={'aria-label': 'Password'})
    country_code = SelectField('Country Code', choices=[('+91', 'India (+91)'), ('+1', 'USA (+1)'), ('+44', 'UK (+44)'), ('+61', 'Australia (+61)')], default='+91', render_kw={'aria-label': 'Country code'})
    mobile_number = StringField('Mobile Number', validators=[Length(min=7, max=12)], render_kw={'aria-label': 'Mobile number', 'pattern': '[0-9]{7,12}', 'title': 'Enter 7-12 digits'})
    submit = SubmitField('Sign Up')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()], render_kw={'aria-label': 'Email address'})
    password = PasswordField('Password', validators=[DataRequired()], render_kw={'aria-label': 'Password'})
    submit = SubmitField('Login')

class CheckoutForm(FlaskForm):
    shipping_address = TextAreaField('Shipping Address', validators=[DataRequired()], render_kw={'aria-label': 'Shipping address'})
    mobile_number = StringField('Mobile Number', validators=[DataRequired(), Length(min=7, max=12)], render_kw={'aria-label': 'Mobile number', 'pattern': '[0-9]{7,12}', 'title': 'Enter 7-12 digits'})
    email = StringField('Email', validators=[DataRequired(), Email()], render_kw={'aria-label': 'Email address'})
    discount_code = StringField('Discount Code (Optional)', render_kw={'aria-label': 'Discount code'})
    payment_method = SelectField('Payment Method', choices=[('cod', 'Cash on Delivery'), ('razorpay', 'Online Payment (Razorpay)')], validators=[DataRequired()], render_kw={'aria-label': 'Payment method'})
    submit = SubmitField('Place Order')

class ProfileForm(FlaskForm):
    mobile_number = StringField('Mobile Number', validators=[Length(min=7, max=12)], render_kw={'aria-label': 'Mobile number', 'pattern': '[0-9]{7,12}', 'title': 'Enter 7-12 digits'})
    country_code = SelectField('Country Code', choices=[('+91', 'India (+91)'), ('+1', 'USA (+1)'), ('+44', 'UK (+44)'), ('+61', 'Australia (+61)')], default='+91', render_kw={'aria-label': 'Country code'})
    submit = SubmitField('Update Profile')

class DiscountCodeForm(FlaskForm):
    code = StringField('Discount Code', validators=[DataRequired(), Length(min=3, max=20)], render_kw={'aria-label': 'Discount code'})
    percentage = FloatField('Discount Percentage', validators=[DataRequired(), NumberRange(min=0.01, max=100)], render_kw={'aria-label': 'Discount percentage'})
    expiry = DateField('Expiry Date', validators=[DataRequired()], format='%Y-%m-%d', render_kw={'aria-label': 'Expiry date'})
    apply_to = SelectField('Apply To', choices=[('all', 'All Products'), ('product', 'Specific Product'), ('category', 'Specific Category')], validators=[DataRequired()], render_kw={'aria-label': 'Apply to'})
    product_id = SelectField('Product', coerce=int, choices=[], render_kw={'aria-label': 'Product'})
    category = SelectField('Category', choices=[('', 'Select Category'), ('puja', 'Puja Items'), ('saree', 'Sarees'), ('other', 'Other')], render_kw={'aria-label': 'Category'})
    submit = SubmitField('Add Discount Code')

class OrderStatusForm(FlaskForm):
    status = SelectField('Status', choices=[
        ('pending', 'Pending'),
        ('processing', 'Processing'),
        ('shipped', 'Shipped'),
        ('delivered', 'Delivered'),
        ('cancelled', 'Cancelled')
    ], validators=[DataRequired()], render_kw={'aria-label': 'Order status'})
    submit = SubmitField('Update Status')

# Flask-Login Setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# HTTPS Redirect
@app.before_request
def require_https():
    if not app.debug and not request.is_secure and not os.getenv('RENDER'):
        return redirect(request.url.replace('http://', 'https://'))

# Backblaze B2 Functions
def upload_to_b2(file, filename, resize_dimensions):
    try:
        img = Image.open(file)
        img.thumbnail(resize_dimensions, Image.Resampling.LANCZOS)
        img = img.resize(resize_dimensions, Image.Resampling.LANCZOS)
        img_byte_arr = BytesIO()
        img.save(img_byte_arr, format=img.format or 'JPEG', quality=85)
        img_byte_arr.seek(0)
        bucket.upload_bytes(
            data_bytes=img_byte_arr.getvalue(),
            file_name=filename
        )
        app.logger.info(f"Successfully uploaded {filename} to Backblaze B2")
        return filename
    except Exception as e:
        app.logger.error(f"Failed to upload to Backblaze B2: {e}")
        raise

def delete_from_b2(filename):
    try:
        file_info = bucket.get_file_info_by_name(filename)
        file_id = file_info.id_
        bucket.delete_file_version(file_id=file_id, file_name=filename)
        app.logger.info(f"Deleted {filename} from Backblaze B2")
    except Exception as e:
        app.logger.error(f"Failed to delete {filename} from Backblaze B2: {e}")

# Updated get_authorized_url (based on test.py)
def get_authorized_url(filename, expiration_seconds=3600):
    try:
        # Verify file exists in bucket
        bucket.get_file_info_by_name(filename)
        # Construct signed URL with auth token
        base_url = f"https://f005.backblazeb2.com/file/mithlanchal-images/{urllib.parse.quote(filename)}"
        auth_token = b2_api.account_info.get_account_auth_token()
        signed_url = f"{base_url}?Authorization={auth_token}"
        app.logger.info(f"Generated signed URL for {filename}: {signed_url}")
        return signed_url
    except Exception as e:
        app.logger.error(f"Failed to generate signed URL for {filename}: {e}", exc_info=True)
        return None

# Function to get applicable discount for a product
def get_product_discount(product):
    discounts = DiscountCode.query.filter(
        or_(
            DiscountCode.product_id == product.id,
            DiscountCode.category == product.category
        ),
        DiscountCode.active == True,
        DiscountCode.expiry > datetime.utcnow()
    ).order_by(DiscountCode.percentage.desc()).first()
    
    if discounts:
        return {
            'discounted_price': product.price * (1 - discounts.percentage / 100),
            'percentage': discounts.percentage
        }
    return None

def init_db():
    with app.app_context():
        try:
            # Drop and recreate schema
            db.session.execute(text('DROP SCHEMA IF EXISTS mithlanchal_store CASCADE;'))
            db.session.execute(text('CREATE SCHEMA IF NOT EXISTS mithlanchal_store;'))
            db.session.commit()
            db.create_all()
            # Set sequence for products.id
            max_id = db.session.query(db.func.max(Product.id)).scalar()
            if max_id is None:
                next_id = 1
            else:
                next_id = max_id + 1
            db.session.execute(text("SELECT setval('mithlanchal_store.products_id_seq', :next_id, false)"), {"next_id": next_id})
            # Create admin user
            if not db.session.query(User).filter_by(email='admin@themithlanchal.com').first():
                admin = User(
                    email='admin@themithlanchal.com',
                    password=generate_password_hash('admin123'),
                    is_admin=True,
                    mobile_number='+919876543210'
                )
                db.session.add(admin)
            db.session.commit()
            app.logger.info("Database initialized successfully")
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Failed to initialize database: {str(e)}")
            raise Exception(f"Database initialization failed: {str(e)}")

# Initialize database after app setup
init_db()

# Routes
@app.route('/')
def index():
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
    product_image_urls = {}
    product_discounts = {}
    for product in products:
        image_urls = []
        for image in product.images:
            try:
                if (not image.signed_url or 
                    not image.expiration_timestamp or 
                    image.expiration_timestamp < datetime.utcnow()):
                    signed_url = get_authorized_url(image.image)
                    if signed_url:
                        image.signed_url = signed_url
                        image.expiration_timestamp = datetime.utcnow() + timedelta(seconds=3600)
                        db.session.commit()
                else:
                    signed_url = image.signed_url
                if signed_url:
                    image_urls.append(signed_url)
                logging.debug(f"Using signed URL for {image.image}: {signed_url}")
            except Exception as e:
                logging.error(f"Error processing signed URL for {image.image}: {str(e)}")
        product_image_urls[product.id] = image_urls
        product_discounts[product.id] = get_product_discount(product)
    app.logger.info(f"Product image URLs: {product_image_urls}")
    form = CartForm()
    return render_template('index.html', products=products, categories=categories, form=form, product_image_urls=product_image_urls, product_discounts=product_discounts)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if request.method == 'POST':
        if form.validate_on_submit():
            email = escape(form.email.data)
            password = form.password.data
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

@app.route('/test-image')
def test_image():
    image = ProductImage.query.first()
    if not image:
        return "No images found in database"
    try:
        signed_url = get_authorized_url(image.image)
        if signed_url:
            return f'<img src="{signed_url}" alt="Test Image" style="max-width: 200px;">'
        else:
            return "Failed to generate signed URL"
    except Exception as e:
        return f"Error generating signed URL: {str(e)}"

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
            if db.session.query(User).filter_by(email=email).first():
                flash('Email already registered')
            elif full_mobile and not re.match(r'^\+[0-9]{10,15}$', full_mobile):
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
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('index'))
    form = AddProductForm()
    if request.method == 'POST':
        if form.validate_on_submit():
            name = escape(form.name.data)
            price = form.price.data
            description = escape(form.description.data)
            category = form.category.data
            images = request.files.getlist('images')
            product = Product(name=name, price=price, description=description, category=category)
            db.session.add(product)
            db.session.flush()
            app.logger.info(f"Added product: {name}, ID: {product.id}")
            for idx, image in enumerate(images, 1):
                if image and image.filename and image.content_type.startswith('image/'):
                    ext = os.path.splitext(secure_filename(image.filename))[1]
                    image_filename = f"products/{uuid.uuid4().hex}{ext}"
                    try:
                        upload_to_b2(image, image_filename, (300, 300))
                        signed_url = get_authorized_url(image_filename)
                        if not signed_url:
                            raise Exception("Failed to generate signed URL")
                        product_image = ProductImage(
                            product_id=product.id,
                            image=image_filename,
                            position=idx,
                            signed_url=signed_url,
                            expiration_timestamp=datetime.utcnow() + timedelta(seconds=3600)
                        )
                        db.session.add(product_image)
                        app.logger.info(f"Added ProductImage: product_id={product.id}, image={image_filename}, position={idx}, signed_url={signed_url}")
                    except Exception as e:
                        flash(f'Failed to upload image {image.filename}: {str(e)}', 'danger')
                        db.session.rollback()
                        app.logger.error(f"Image upload failed for {image_filename}: {e}", exc_info=True)
                        return redirect(url_for('admin'))
            try:
                db.session.commit()
                app.logger.info("Database commit successful for product and images")
                flash('Product and images saved successfully', 'success')
            except Exception as e:
                db.session.rollback()
                app.logger.error(f"Database commit failed: {e}", exc_info=True)
                flash('Failed to save product/images to database', 'danger')
            return redirect(url_for('index'))
        else:
            flash('Form validation failed. Please check your input.', 'danger')
            app.logger.debug(f"Add product form errors: {form.errors}")
    products = db.session.query(Product).all()
    product_image_urls = {}
    for product in products:
        image_urls = []
        for image in product.images:
            try:
                if (not image.signed_url or 
                    not image.expiration_timestamp or 
                    image.expiration_timestamp < datetime.utcnow()):
                    signed_url = get_authorized_url(image.image)
                    if signed_url:
                        image.signed_url = signed_url
                        image.expiration_timestamp = datetime.utcnow() + timedelta(seconds=3600)
                        db.session.commit()
                else:
                    signed_url = image.signed_url
                if signed_url:
                    image_urls.append(signed_url)
                logging.debug(f"Using signed URL for {image.image}: {signed_url}")
            except Exception as e:
                logging.error(f"Error processing signed URL for {image.image}: {str(e)}")
        product_image_urls[product.id] = image_urls
    return render_template('admin.html', products=products, form=form, product_image_urls=product_image_urls)

@app.route('/admin/edit/<int:product_id>', methods=['GET', 'POST'])
@login_required
def edit_product(product_id):
    if not current_user.is_admin:
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('index'))
    product = db.session.query(Product).get_or_404(product_id)
    form = EditProductForm(obj=product)
    if request.method == 'POST':
        if form.validate_on_submit():
            product.name = escape(form.name.data)
            product.price = form.price.data
            product.description = escape(form.description.data)
            product.category = form.category.data
            new_images = request.files.getlist('images')
            if new_images:
                max_position = max([img.position for img in product.images], default=0)
                for idx, image in enumerate(new_images, max_position + 1):
                    if image and image.filename and image.content_type.startswith('image/'):
                        ext = os.path.splitext(secure_filename(image.filename))[1]
                        image_filename = f"products/{uuid.uuid4().hex}{ext}".lower()
                        try:
                            upload_to_b2(image, image_filename, (300, 300))
                            signed_url = get_authorized_url(image_filename)
                            if not signed_url:
                                raise Exception("Failed to generate signed URL")
                            product_image = ProductImage(
                                product_id=product.id,
                                image=image_filename,
                                position=idx,
                                signed_url=signed_url,
                                expiration_timestamp=datetime.utcnow() + timedelta(seconds=3600)
                            )
                            db.session.add(product_image)
                            app.logger.info(f"Added ProductImage: product_id={product.id}, image={image_filename}, position={idx}, signed_url={signed_url}")
                        except Exception as e:
                            flash(f'Failed to upload image {image.filename}: {str(e)}', 'danger')
                            db.session.rollback()
                            app.logger.error(f"Image upload failed for {image_filename}: {e}", exc_info=True)
                            return redirect(url_for('edit_product', product_id=product.id))
            delete_images = request.form.getlist('delete_images')
            for image_id in delete_images:
                image = ProductImage.query.get(int(image_id))
                if image and image.product_id == product.id:
                    delete_from_b2(image.image)
                    db.session.delete(image)
            for idx, image in enumerate(product.images):
                position = request.form.get(f'position_{image.id}')
                if position:
                    image.position = int(position)
            try:
                db.session.commit()
                app.logger.info("Database commit successful for edited product and images")
                flash('Product updated successfully', 'success')
            except Exception as e:
                db.session.rollback()
                app.logger.error(f"Database commit failed: {e}", exc_info=True)
                flash('Failed to update product/images', 'danger')
            return redirect(url_for('admin'))
        else:
            flash('Form validation failed. Please check your input.', 'danger')
            app.logger.debug(f"Edit product form errors: {form.errors}")
    images = []
    for image in product.images:
        try:
            if (not image.signed_url or 
                not image.expiration_timestamp or 
                image.expiration_timestamp < datetime.utcnow()):
                signed_url = get_authorized_url(image.image)
                if signed_url:
                    image.signed_url = signed_url
                    image.expiration_timestamp = datetime.utcnow() + timedelta(seconds=3600)
                    db.session.commit()
            else:
                signed_url = image.signed_url
            if signed_url:
                images.append((signed_url, image.id))
            logging.debug(f"Using signed URL for {image.image}: {signed_url}")
        except Exception as e:
            logging.error(f"Error processing signed URL for {image.image}: {str(e)}")
    return render_template('edit_product.html', product=product, form=form, images=images)

@app.route('/admin/delete/<int:product_id>')
@login_required
def delete_product(product_id):
    if not current_user.is_admin:
        flash('You are not authorized to access this page.', 'danger')
        return redirect(url_for('index'))
    product = db.session.query(Product).get_or_404(product_id)
    db.session.query(CartItem).filter_by(product_id=product_id).delete()
    for image in product.images:
        delete_from_b2(image.image)
    db.session.delete(product)
    db.session.commit()
    flash('Product deleted successfully')
    return redirect(url_for('admin'))

@app.route('/admin/discounts', methods=['GET', 'POST'])
@login_required
def admin_discounts():
    if not current_user.is_admin:
        return redirect(url_for('index'))
    form = DiscountCodeForm()
    # Populate product choices
    products = db.session.query(Product).all()
    form.product_id.choices = [(0, 'Select Product')] + [(p.id, p.name) for p in products]
    if request.method == 'POST':
        if form.validate_on_submit():
            code = escape(form.code.data).upper()
            percentage = form.percentage.data
            expiry = form.expiry.data
            apply_to = form.apply_to.data
            product_id = form.product_id.data if apply_to == 'product' and form.product_id.data != 0 else None
            category = form.category.data if apply_to == 'category' else None
            if db.session.query(DiscountCode).filter_by(code=code).first():
                flash('Discount code already exists', 'danger')
            else:
                discount = DiscountCode(
                    code=code,
                    percentage=percentage,
                    expiry=expiry,
                    product_id=product_id,
                    category=category
                )
                db.session.add(discount)
                db.session.commit()
                flash('Discount code added successfully', 'success')
            return redirect(url_for('admin_discounts'))
        else:
            flash('Invalid form validation failed. Please check your input.', 'danger')
            app.logger.debug(f"Discount code form errors: {form.errors}")
    discounts = db.session.query(DiscountCode).all()
    return render_template('admin_discounts.html', discounts=discounts, form=form)

@app.route('/admin/orders', methods=['GET', 'POST'])
@login_required
def admin_orders():
    if not current_user.is_admin:
        return redirect(url_for('index'))
    form = OrderStatusForm()
    if request.method == 'POST':
        if form.validate_on_submit():
            order_id = request.form.get('order_id')
            new_status = form.status.data
            order = db.session.query(Order).get_or_404(id=order_id)
            old_status = order.status
            order.status = new_status
            db.session.commit()
            try:
                items_list = ''
                for item in order.order_items:
                    items_list += f'- {item.product.name} (x{item.quantity}): ₹{item.price * item.quantity:.2f}\n'
                msg = Message(
                    subject=f"The Mithlanchal - Order #{order.id} Status Updated",
                    recipients=[order.email],
                    body=f"""
Dear Customer,

Your order status has been updated!

Order #{order.id}
Date: {order.created_at.strftime('%Y-%m-%d %H:%M') if order.created_at else 'Not available'}
Previous Status: {old_status.title()}
New Status: {new_status.title()}
Total: ₹{order.total:.2f}
{f'Discount: ₹{order.discount_applied:.2f}' if order.discount_applied > 0 else ''}
Shipping Address: {order.shipping_address}
Mobile: {order.mobile_number}

Items:
{items_list}

Thank you for shopping with The Mithlanchal!

Best,
The Mithlanchal Team
"""
                )
                mail.send(msg)
                flash(f'Order #{order.id} status updated to {new_status.title()} and user notified successfully.', 'success')
            except Exception as e:
                app.logger.error(f"Email notification failed: {e}")
                flash(f'Order #{order.id} status updated to {new_status.title()}, but email notification failed.', 'warning')
            return redirect(url_for('admin_orders'))
        else:
            flash('Form validation failed. Please check your input.', 'danger')
    orders = db.session.query(Order).order_by(Order.id.desc()).all()
    return render_template('admin_orders.html', orders=orders, form=form)

@app.route('/product/<int:product_id>')
def product(product_id):
    product = Product.query.get_or_404(product_id)
    images = ProductImage.query.filter_by(product_id=product_id).all()
    image_urls = []
    for image in images:
        try:
            if (not image.signed_url or 
                not image.expiration_timestamp or 
                image.expiration_timestamp < datetime.utcnow()):
                signed_url = get_authorized_url(image.image)
                if signed_url:
                    image.signed_url = signed_url
                    image.expiration_timestamp = datetime.utcnow() + timedelta(seconds=3600)
                    db.session.commit()
            else:
                signed_url = image.signed_url
            if signed_url:
                image_urls.append(signed_url)
            logging.debug(f'Using signed URL for {image.image}: {signed_url}')
        except Exception as e:
            logging.error(f'Error processing signed URL for {image.image}: {str(e)}')
    form = CartForm(product_id=product_id)
    discount = get_product_discount(product)
    app.logger.info(f"Product {product_id} image URLs: {image_urls}")
    return render_template('product.html', product=product, image_urls=image_urls, form=form, discount=discount)

@app.route('/cart', methods=['GET', 'POST'])
@login_required
def cart():
    csrf_form = CSRFOnlyForm()
    if request.method == 'POST':
        form = CartForm(request.form)
        if form.validate_on_submit():
            product_id = form.product_id.data
            quantity = form.quantity.data
            cart_item = db.session.query(CartItem).filter_by(user_id=current_user.id, product_id=product_id).first()
            if cart_item:
                cart_item.quantity += quantity
            else:
                cart_item = CartItem(user_id=current_user.id, product_id=product_id, quantity=quantity)
                db.session.add(cart_item)
            db.session.commit()
            flash('Item added to cart', 'success')
            return redirect(url_for('cart'))
        else:
            flash('Failed to add item to cart. Please try again.', 'danger')
            app.logger.debug(f"Add to cart form errors: {form.errors}")
            return redirect(url_for('cart'))
    cart_items = db.session.query(CartItem).filter_by(user_id=current_user.id).all()
    cart_image_urls = {}
    cart_discounts = {}
    subtotal = 0.0
    total_discount = 0.0
    
    for item in cart_items:
        image_urls = []
        for image in item.product.images:
            try:
                if (not image.signed_url or 
                    not image.expiration_timestamp or 
                    image.expiration_timestamp < datetime.utcnow()):
                    signed_url = get_authorized_url(image.image)
                    if signed_url:
                        image.signed_url = signed_url
                        image.expiration_timestamp = datetime.utcnow() + timedelta(seconds=3600)
                        db.session.commit()
                else:
                    signed_url = image.signed_url
                if signed_url:
                    image_urls.append(signed_url)
                logging.debug(f"Using signed URL for {image.image}: {signed_url}")
            except Exception as e:
                logging.error(f"Error processing signed URL for {image.image}: {str(e)}")
        cart_image_urls[item.product_id] = image_urls
        discount = get_product_discount(item.product)
        cart_discounts[item.product_id] = discount
        item_subtotal = item.product.price * item.quantity
        subtotal += item_subtotal
        if discount:
            total_discount += (item.product.price - discount.get('discounted_price', item.product.price)) * item.quantity
    total = round(subtotal - total_discount, 2)
    app.logger.info(f"Cart image URLs: {cart_image_urls}")
    return render_template('cart.html', cart_items=cart_items, total=total, cart_image_urls=cart_image_urls, form=csrf_form, cart_discounts=cart_discounts, subtotal=round(subtotal, 2), total_discount=round(total_discount, 2))

@app.route('/cart/remove/<int:cart_item_id>', methods=['POST'])
@login_required
def remove_from_cart(cart_item_id):
    cart_item = db.session.query(CartItem).get_or_404(cart_item_id)
    if cart_item.user_id != current_user.id:
        flash('Unauthorized action', 'danger')
        return redirect(url_for('cart'))
    db.session.delete(cart_item)
    db.session.commit()
    flash('Item removed from cart', 'success')
    return redirect(url_for('cart'))

@app.route('/cart/increase/<int:cart_item_id>', methods=['POST'])
@login_required
def increase_cart_item(cart_item_id):
    cart_item = db.session.query(CartItem).get_or_404(cart_item_id)
    if cart_item.user_id != current_user.id:
        flash('Unauthorized action', 'danger')
        return redirect(url_for('cart'))
    cart_item.quantity += 1
    db.session.commit()
    flash('Quantity increased', 'success')
    return redirect(url_for('cart'))

@app.route('/cart/decrease/<int:cart_item_id>', methods=['POST'])
@login_required
def decrease_cart_item(cart_item_id):
    cart_item = db.session.query(CartItem).get_or_404(cart_item_id)
    if cart_item.user_id != current_user.id:
        flash('Unauthorized action', 'danger')
        return redirect(url_for('cart'))
    if cart_item.quantity > 1:
        cart_item.quantity -= 1
        db.session.commit()
        flash('Quantity decreased', 'success')
    else:
        db.session.delete(cart_item)
        db.session.commit()
        flash('Item removed from cart', 'success')
    return redirect(url_for('cart'))

@app.route('/checkout', methods=['GET', 'POST'])
@login_required
def checkout():
    form = CheckoutForm()
    cart_items = db.session.query(CartItem).filter_by(user_id=current_user.id).all()
    if not cart_items:
        flash('Your cart is empty')
        return redirect(url_for('cart'))
    cart_discounts = {}
    subtotal = 0.0
    total_discount = 0.0
    
    for item in cart_items:
        discount = get_product_discount(item.product)
        cart_discounts[item.product_id] = discount
        item_subtotal = item.product.price * item.quantity
        subtotal += item_subtotal
        if discount:
            total_discount += (item.product.price - discount.get('discounted_price', item.product.price)) * item.quantity
    
    total = round(subtotal - total_discount, 2)
    discount_value = 0.0
    discount_code = None
    
    if request.method == 'POST':
        if form.validate_on_submit():
            shipping_address = escape(form.shipping_address.data)
            mobile_number = escape(form.mobile_number.data)
            email = escape(form.email.data)
            payment_method = form.payment_method.data
            discount_code_str = escape(form.discount_code.data).upper()
            if discount_code_str:
                now = datetime.utcnow()
                discount_code = db.session.query(DiscountCode).filter(
                    DiscountCode.code == discount_code_str,
                    DiscountCode.active == True,
                    DiscountCode.expiry >= now
                ).first()
                if discount_code:
                    applicable = True
                    for item in cart_items:
                        if discount_code.product_id and discount_code.product_id != item.product.id:
                            applicable = False
                        elif discount_code.category and discount_code.category != item.product.category:
                            applicable = False
                    if applicable:
                        discount = round(total * (discount_code.percentage / 100), 2)
                        total = round(total - discount, 2)
                        discount_value = discount
                    else:
                        flash('Discount code is not applicable to items in your cart')
                        return render_template('checkout.html', cart_items=cart_items, total=total, discount=discount_value, form=form, user_email=current_user.email, cart_discounts=cart_discounts, subtotal=round(subtotal, 2), total_discount=round(total_discount, 2))
                else:
                    flash('Invalid or expired discount code')
                    return render_template('checkout.html', cart_items=cart_items, total=total, discount=discount_value, form=form, user_email=current_user.email, cart_discounts=cart_discounts, subtotal=round(subtotal, 2), total_discount=round(total_discount, 2))
            order = Order(
                user_id=current_user.id,
                total=total,
                payment_method=payment_method,
                status='pending',
                shipping_address=shipping_address,
                mobile_number=mobile_number,
                email=email,
                discount_code_id=discount_code.id if discount_code else None,
                discount_applied=discount_value
            )
            db.session.add(order)
            for item in cart_items:
                order_item = OrderItem(
                    order=order,
                    product_id=item.product_id,
                    quantity=item.quantity,
                    price=item.product.price if not cart_discounts.get(item.product_id) else cart_discounts[item.product_id]['discounted_price']
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
                    return render_template('checkout.html', order=razorpay_order, cart_items=cart_items, total=total, razorpay_key=os.getenv('RAZORPAY_KEY'), db_order_id=order.id, discount=discount_value, form=form, user_email=current_user.email, cart_discounts=cart_discounts, subtotal=round(subtotal, 2), total_discount=round(total_discount, 2))
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
{f'Discount: ₹{order.discount_applied:.2f}' if order.discount_applied > 0 else ''}
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
    return render_template('checkout.html', cart_items=cart_items, total=total, discount=discount_value, form=form, user_email=current_user.email, cart_discounts=cart_discounts, subtotal=round(subtotal, 2), total_discount=round(total_discount, 2))

@app.route('/payment/success', methods=['POST'])
@login_required
def payment_success():
    payment_id = request.form.get('razorpay_payment_id')
    order_id = request.form.get('razorpay_order_id')
    signature = request.form.get('razorpay_signature')
    db_order_id = request.form.get('order_id')
    params_dict = {
        'razorpay_order_id': order_id,
        'razorpay_payment_id': payment_id,
        'razorpay_signature': signature
    }
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
        flash('Payment successful! Your order has been confirmed.')
        return redirect(url_for('order_confirmation', order_id=order.id))
    except Exception as e:
        flash(f'Payment verification failed: {str(e)}')
        return redirect(url_for('checkout'))

@app.route('/orders')
@login_required
def orders():
    user_orders = db.session.query(Order).filter_by(user_id=current_user.id).order_by(Order.id.desc()).all()
    return render_template('orders.html', orders=user_orders)

@app.route('/account', methods=['GET', 'POST'])
@login_required
def account():
    form = ProfileForm()
    if request.method == 'POST':
        if form.validate_on_submit():
            country_code = form.country_code.data
            mobile_number = escape(form.mobile_number.data)
            full_mobile = f"{country_code}{mobile_number}" if mobile_number else None
            if full_mobile and not re.match(r'^\+[0-9]{10,15}$', full_mobile):
                flash('Invalid mobile number format', 'danger')
            elif full_mobile and db.session.query(User).filter(User.id != current_user.id, mobile_number=full_mobile).first():
                flash('Mobile number already registered by another user', 'danger')
            else:
                current_user.mobile_number = full_mobile
                db.session.commit()
                flash('Profile updated successfully', 'success')
                return redirect(url_for('account'))
        else:
            flash('Form validation failed. Please check your input.', 'danger')
            app.logger.debug(f"Profile form errors: {form.errors}")
    return render_template('account.html', form=form)

@app.route('/order/<int:order_id>')
@login_required
def order_confirmation(order_id):
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
            f'₹{item.price:.2f}',
            item.quantity,
            f'₹{item.price * item.quantity:.2f}'
        ])
    data.append(['', '', 'Subtotal', f'₹{sum(item.price * item.quantity for item in order.order_items):.2f}'])
    if order.discount_applied > 0:
        data.append(['', '', 'Discount', f'-₹{order.discount_applied:.2f}'])
    data.append(['', '', 'Total', f'₹{order.total:.2f}'])
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

@app.route('/cancel_order/<int:order_id>', methods=['POST'])
@login_required
def cancel_order(order_id):
    order = db.session.query(Order).get_or_404(order_id)
    if order.user_id != current_user.id:
        flash('You are not authorized to cancel this order.', 'danger')
        return redirect(url_for('orders'))
    if order.status not in ['pending', 'processing']:
        flash('This order cannot be cancelled as it is already ' + order.status + '.', 'danger')
        return redirect(url_for('order_confirmation', order_id=order.id))
    order.status = 'cancelled'
    db.session.commit()
    try:
        items_list = ''
        for item in order.order_items:
            items_list += f'- {item.product.name} (x{item.quantity}): ₹{item.price * item.quantity:.2f}\n'
        msg = Message(
            subject=f"The Mithlanchal - Order #{order.id} Cancelled",
            recipients=[order.email],
            body=f"""
Dear Customer,

Your order has been cancelled as per your request.

Order #{order.id}
Date: {order.created_at.strftime('%Y-%m-%d %H:%M') if order.created_at else ''}
Status: Cancelled
Total: ₹{order.total:.2f}
{f'Discount: ₹{order.discount_applied:.2f}' if order.discount_applied > 0 else ''}
Shipping Address: {order.shipping_address}
Mobile: {order.mobile_number}

Items:
{items_list}

If you have any questions, please contact us.

Best,
The Mithlanchal Team
"""
        )
        mail.send(msg)
        flash('Order cancelled successfully and user notified by email.', 'success')
    except Exception as e:
        app.logger.error(f"Email notification failed: {e}")
        flash('Order cancelled successfully, but email notification failed.', 'warning')
    return redirect(url_for('order_confirmation', order_id=order.id))

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
def logout():
    logout_user()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=os.getenv('FLASK_DEBUG', 'True') == 'True')