# migrations/env.py
from alembic import context
from sqlalchemy import engine_from_config, pool
from sqlalchemy.sql import text
from logging.config import fileConfig
import os
from flask import current_app
from extensions import db  # Adjust import based on your project structure

# Define the Alembic Config object, which provides access to the values within the .ini file in use.
config_file = context.config

# Interpret the configuration file for Python logging.
if config_file.config_file_name is not None:
    fileConfig(config_file.config_file_name)

# Set the database URL from Flask config
config_file.set_main_option('sqlalchemy.url', current_app.config.get('SQLALCHEMY_DATABASE_URI'))

# Add your model's MetaData object here
target_metadata = db.metadata

def run_migrations_offline():
    """Run migrations in 'offline' mode."""
    url = config_file.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()

def run_migrations_online():
    """Run migrations in 'online' mode."""
    connectable = engine_from_config(
        config_file.get_section(config_file.config_ini_section),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        # Set the search path to mithlanchal_store using text()
        connection.execute(text("SET search_path TO mithlanchal_store"))
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            version_table_schema='mithlanchal_store',  # Specify schema for alembic_version
        )

        with context.begin_transaction():
            context.run_migrations()

if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()