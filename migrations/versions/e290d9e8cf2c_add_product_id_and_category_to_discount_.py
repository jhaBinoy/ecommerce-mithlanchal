"""Add product_id and category to discount_codes

Revision ID: e290d9e8cf2c
Revises: 
Create Date: 2025-05-28 01:28:13.725248
"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'e290d9e8cf2c'
down_revision = None
branch_labels = None
depends_on = None

def upgrade():
    # Add product_id and category columns to discount_codes
    op.add_column('discount_codes', sa.Column('product_id', sa.Integer(), nullable=True), schema='mithlanchal_store')
    op.add_column('discount_codes', sa.Column('category', sa.String(length=50), nullable=True), schema='mithlanchal_store')
    op.create_foreign_key(None, 'discount_codes', 'products', ['product_id'], ['id'], source_schema='mithlanchal_store', referent_schema='mithlanchal_store')

def downgrade():
    # Remove foreign key and columns
    op.drop_constraint(None, 'discount_codes', schema='mithlanchal_store', type_='foreignkey')
    op.drop_column('discount_codes', 'category', schema='mithlanchal_store')
    op.drop_column('discount_codes', 'product_id', schema='mithlanchal_store')