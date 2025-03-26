from flask import Flask, request, jsonify, send_file
from flask_mysqldb import MySQL
from flask_jwt_extended import JWTManager, create_access_token, jwt_required
import bcrypt
import pyotp
import qrcode
import io
import pymysql
from datetime import timedelta

app = Flask(__name__)

# MySQL Configuration
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'  
app.config['MYSQL_PASSWORD'] = ''  
app.config['MYSQL_DB'] = 'taskdb'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'
mysql = MySQL(app)

# JWT Configuration
app.config['JWT_SECRET_KEY'] = 'supersecretkey'  
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=10)
jwt = JWTManager(app)


def init_db():
    """ Creates the database and tables if they don't exist """
    connection = pymysql.connect(host='localhost', user='root', password='')
    cursor = connection.cursor()
    cursor.execute("CREATE DATABASE IF NOT EXISTS taskdb")
    connection.commit()
    connection.close()

    # Connect to the new database
    connection = pymysql.connect(host='localhost', user='root', password='', database='taskdb')
    cursor = connection.cursor()

    # Create Users Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(50) UNIQUE NOT NULL,
            password VARCHAR(500) NOT NULL,
            twofa_secret VARCHAR(256) NOT NULL
        )
    """)

    # Create Products Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS products (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(100) NOT NULL,
            description VARCHAR(255),
            price DECIMAL(10,2),
            quantity INT
        )
    """)

    connection.commit()
    connection.close()
    print("Database and tables initialized successfully.")


@app.route('/register', methods=['POST'])
def register():
    """ User Registration: Store username, hashed password, and 2FA secret """
    data = request.get_json()
    username = data['username']
    password = data['password']

    # Check if username already exists
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
    existing_user = cursor.fetchone()
    if existing_user:
        cursor.close()
        return jsonify({"error": "Username already taken"}), 400

    # Hash password
    hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    # Generate a unique 2FA secret (but don't return it)
    twofa_secret = pyotp.random_base32()

    # Store in DB
    cursor.execute("INSERT INTO users (username, password, twofa_secret) VALUES (%s, %s, %s)",
                   (username, hashed_pw.decode('utf-8'), twofa_secret))
    mysql.connection.commit()
    cursor.close()

    return jsonify({"message": "User registered successfully"}), 201


@app.route('/login', methods=['POST'])
def login():
    """ User Login: Validate username & password and return QR code """
    data = request.get_json()
    username = data['username']
    password = data['password']

    # Fetch user details from DB
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
    user = cursor.fetchone()
    cursor.close()

    if not user or not bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
        return jsonify({"error": "Invalid username or password"}), 401

    # Generate QR Code for 2FA
    twofa_secret = user['twofa_secret']
    otp_uri = pyotp.totp.TOTP(twofa_secret).provisioning_uri(username, issuer_name="FlaskAuthApp")

    qr = qrcode.make(otp_uri)
    img = io.BytesIO()
    qr.save(img, format="PNG")
    img.seek(0)

    return send_file(img, mimetype='image/png')


@app.route('/verify-2fa', methods=['POST'])
def verify_2fa():
    """ Verify the 6-digit code from Google Authenticator and return JWT token """
    data = request.get_json()
    username = data['username']
    twofa_code = data['2fa_code']

    # Fetch user details
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT twofa_secret FROM users WHERE username = %s", (username,))
    user = cursor.fetchone()
    cursor.close()

    if not user:
        return jsonify({"error": "User not found"}), 404

    # Validate 2FA code
    totp = pyotp.TOTP(user['twofa_secret'])
    if not totp.verify(twofa_code):
        return jsonify({"error": "Invalid 2FA code"}), 401

    # Generate JWT Token (valid for 10 minutes)
    access_token = create_access_token(identity=username)
    return jsonify({"token": access_token})


# JWT-Protected CRUD Operations

@app.route('/products', methods=['POST'])
@jwt_required()
def create_product():
    """ Create a new product """
    data = request.get_json()
    cursor = mysql.connection.cursor()
    cursor.execute("INSERT INTO products (name, description, price, quantity) VALUES (%s, %s, %s, %s)",
                   (data['name'], data['description'], data['price'], data['quantity']))
    mysql.connection.commit()
    cursor.close()
    return jsonify({"message": "Product created successfully"}), 201


@app.route('/products', methods=['GET'])
@jwt_required()
def get_products():
    """ Retrieve all products """
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT * FROM products")
    products = cursor.fetchall()
    cursor.close()
    return jsonify(products)


@app.route('/products/<int:product_id>', methods=['PUT'])
@jwt_required()
def update_product(product_id):
    """ Update product details """
    data = request.get_json()
    cursor = mysql.connection.cursor()
    cursor.execute("UPDATE products SET name=%s, description=%s, price=%s, quantity=%s WHERE id=%s",
                   (data['name'], data['description'], data['price'], data['quantity'], product_id))
    mysql.connection.commit()
    cursor.close()
    return jsonify({"message": "Product updated successfully"})


@app.route('/products/<int:product_id>', methods=['DELETE'])
@jwt_required()
def delete_product(product_id):
    """ Delete a product """
    cursor = mysql.connection.cursor()
    cursor.execute("DELETE FROM products WHERE id = %s", (product_id,))
    mysql.connection.commit()
    cursor.close()
    return jsonify({"message": "Product deleted successfully"})


if __name__ == '__main__':
    print("Initializing database...")
    init_db()  # Initialize database and tables
    print("Starting Flask server...")
    app.run(debug=True)
