# test_db.py
import psycopg2
from urllib.parse import urlparse

db_url = "postgresql://admin:o6EsRZd9mQaSEmS6XEKH6cloIuKyrh3c@dpg-d0lo3pogjchc73f8k8l0-a.oregon-postgres.render.com/store_lt18_sykd?sslmode=require"
url = urlparse(db_url)
conn = None
try:
    conn = psycopg2.connect(
        database=url.path[1:],
        user=url.username,
        password=url.password,
        host=url.hostname,
        port=url.port,
        sslmode="require"
    )
    print("Connection successful!")
    cursor = conn.cursor()
    cursor.execute("SELECT version();")
    print(f"PostgreSQL version: {cursor.fetchone()[0]}")
    cursor.close()
except Exception as e:
    print(f"Connection failed: {e}")
finally:
    if conn:
        conn.close()