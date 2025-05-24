import os
from b2sdk.v2 import B2Api, InMemoryAccountInfo
from PIL import Image
from io import BytesIO
from flask_sqlalchemy import SQLAlchemy
from flask import Flask
import uuid
from dotenv import load_dotenv
load_dotenv()

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'postgresql://admin:o6EsRZd9mQaSEmS6XEKH6cloIuKyrh3c@dpg-d0lo3pogjchc73f8k8l0-a.oregon-postgres.render.com/store_lt18_sykd?sslmode=require')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Load credentials from environment variables
B2_KEY_ID = os.getenv('B2_KEY_ID')
B2_APPLICATION_KEY = os.getenv('B2_APPLICATION_KEY')
B2_BUCKET_NAME = 'mithlanchal-images'

# Check if credentials are set
if not B2_KEY_ID or not B2_APPLICATION_KEY:
    print("Error: B2_KEY_ID or B2_APPLICATION_KEY not set.")
    exit(1)

# Initialize B2 API
info = InMemoryAccountInfo()
b2_api = B2Api(info)
try:
    b2_api.authorize_account("production", B2_KEY_ID, B2_APPLICATION_KEY)
except Exception as e:
    print(f"Authorization failed: {e}")
    exit(1)

def upload_to_b2(file_path, filename, resize_dimensions):
    img = Image.open(file_path)
    img.thumbnail(resize_dimensions, Image.Resampling.LANCZOS)
    img = img.resize(resize_dimensions, Image.Resampling.LANCZOS)
    img_byte_arr = BytesIO()
    img.save(img_byte_arr, format=img.format or 'JPEG', quality=85)
    img_byte_arr.seek(0)
    bucket = b2_api.get_bucket_by_name(B2_BUCKET_NAME)
    bucket.upload_bytes(
        data_bytes=img_byte_arr.getvalue(),
        file_name=filename
    )
    return filename

class Product(db.Model):
    __tablename__ = 'products'
    id = db.Column(db.Integer, primary_key=True)
    image = db.Column(db.String(255))

class ProductImage(db.Model):
    __tablename__ = 'product_images'
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey('products.id'), nullable=False)
    image = db.Column(db.String(255), nullable=False)
    position = db.Column(db.Integer, nullable=False, default=1)

with app.app_context():
    products = db.session.query(Product).filter(Product.image.isnot(None)).all()
    for product in products:
        image_path = os.path.join('static/uploads', product.image.split('/')[-1])
        if os.path.exists(image_path):
            new_filename = f"products/{uuid.uuid4().hex}{os.path.splitext(image_path)[1]}".lower()
            try:
                upload_to_b2(image_path, new_filename, (300, 300))
                product_image = ProductImage(
                    product_id=product.id,
                    image=new_filename,
                    position=1
                )
                db.session.add(product_image)
            except Exception as e:
                print(f"Failed to migrate image for product {product.id}: {e}")
    db.session.commit()