BEGIN TRANSACTION;

CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(100) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    is_admin BOOLEAN,
    mobile_number VARCHAR(15) UNIQUE
);

INSERT INTO users (id, email, password, is_admin, mobile_number) VALUES
(1, 'admin@themithlanchal.com', 'scrypt:32768:8:1$ZZ7QcwRkCi3cyaSS$e4e75a830c70ea4199f29b5b91ccfb674f94d5fb3fc2853fb1787ba8dd11aaa7222b19ba761f2249ca67d50ddd24c31990598c398a1d85e91832aaf71d1de5ba', TRUE, '+919876543210'),
(2, 'binoyjha5@gmail.com', 'scrypt:32768:8:1$VVLqKoKa9IbwioTN$735c87cc5822ccf292cc2f8f38272d480dc4ebd0ebf7b33d938c7cab7a92d93ef71a66ad89f7cb7400b4196823c22af708eaaa2308a118b0cb7c4f04df59dcfc', FALSE, '+919038611486');

CREATE TABLE products (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    price FLOAT NOT NULL,
    description TEXT,
    image VARCHAR(200),
    category VARCHAR(50)
);

INSERT INTO products (id, name, price, description, image, category) VALUES
(1, 'test1', 1000.0, 'test1', 'uploads/ff822cc141394ec2a9f32322d3f7a832.jpg', 'puja');

CREATE TABLE discount_codes (
    id SERIAL PRIMARY KEY,
    code VARCHAR(20) NOT NULL UNIQUE,
    percentage FLOAT NOT NULL,
    expiry TIMESTAMP NOT NULL,
    active BOOLEAN
);

CREATE TABLE cart_items (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id),
    product_id INTEGER NOT NULL REFERENCES products(id),
    quantity INTEGER
);

CREATE TABLE orders (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id),
    total FLOAT NOT NULL,
    payment_method VARCHAR(20) NOT NULL,
    payment_id VARCHAR(100),
    status VARCHAR(20),
    created_at TIMESTAMP,
    shipping_address TEXT NOT NULL,
    mobile_number VARCHAR(15) NOT NULL,
    email VARCHAR(100) NOT NULL,
    discount_code_id INTEGER REFERENCES discount_codes(id),
    discount_applied FLOAT
);

CREATE TABLE order_items (
    id SERIAL PRIMARY KEY,
    order_id INTEGER NOT NULL REFERENCES orders(id),
    product_id INTEGER NOT NULL REFERENCES products(id),
    quantity INTEGER NOT NULL,
    price FLOAT NOT NULL
);

COMMIT;