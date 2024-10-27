from flask import Flask, jsonify, request, g, session
from dotenv import load_dotenv
import os
import logging
import time
from flask_sqlalchemy import SQLAlchemy
import requests
import asyncio
import aiohttp
import bcrypt
from sqlalchemy import text
import hashlib

# Load environment variables from .env file
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')  # Needed for session management

# Configure the database connection using the environment variable
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
db = SQLAlchemy(app)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@app.route('/')
def index():
    return jsonify({"message": "Composite Microservice is running!"})

# Middleware to log before each request
@app.before_request
def before_request_logging():
    g.start_time = time.time()
    logger.info(f"Before Request - Method: {request.method} Path: {request.path}")

# Middleware to log after each request
@app.after_request
def after_request_logging(response):
    duration = time.time() - g.start_time
    logger.info(f"After Request - Method: {request.method} Path: {request.path} Status: {response.status_code} Duration: {duration:.4f}s")
    return response

# Helper function to verify password
def verify_password(stored_password_hash, provided_password):
    return bcrypt.checkpw(provided_password.encode('utf-8'), stored_password_hash)

# Customer login


@app.route('/customer/login', methods=['POST'])
def customer_login():
    try:
        if request.content_type != 'application/json':
            return jsonify({"error": "Content-Type must be application/json"}), 415

        data = request.get_json()
        email = data.get('email')
        password = data.get('password')

        if not email or not password:
            return jsonify({"error": "Email and password are required"}), 400

        # Use the text function from SQLAlchemy to explicitly declare the query
        query = text("SELECT * FROM Customer WHERE email = :email")
        customer = db.session.execute(query, {"email": email}).fetchone()

        if customer:
            # Debugging log to confirm fetching of customer
            logger.info(f"Customer fetched: {customer}")

            # Access the password hash from the row
            password_hash = customer.password_hash

            # Hash the provided password using SHA-256
            provided_password_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()

            # Verify the password
            if provided_password_hash == password_hash:
                session['user_id'] = customer.customer_id
                return jsonify({"state": True, "message": "Login successful"})

        return jsonify({"state": False, "message": "Incorrect email or password"}), 401
    except Exception as e:
        logger.error(f"Error during login: {e}")
        return jsonify({"error": "An internal server error occurred"}), 500


# GET - Retrieve customer info
@app.route('/customer/<int:customer_id>', methods=['GET'])
def get_customer_info(customer_id):
    try:
        # Directly query the Customer table for the given customer_id
        query = text("SELECT * FROM Customer WHERE customer_id = :customer_id")
        customer = db.session.execute(query, {"customer_id": customer_id}).fetchone()
        
        if customer:
            # Construct the customer info dictionary from the fetched row
            customer_info = {
                "customer_id": customer.customer_id,
                "name": customer.name,
                "email": customer.email,
                "address": customer.address,
                "phone": customer.phone
            }
            return jsonify(customer_info)
        else:
            return jsonify({'error': 'Customer not found'}), 404
    except Exception as e:
        logger.error(f"Error retrieving customer: {e}")
        return jsonify({'error': 'Failed to retrieve customer information'}), 500

# POST - Create a new customer
@app.route('/customer', methods=['POST'])
def create_customer():
    if request.content_type != 'application/json':
        return jsonify({"error": "Content-Type must be application/json"}), 415

    data = request.get_json()
    name = data.get('name')
    email = data.get('email')
    address = data.get('address')
    phone = data.get('phone')
    password_hash = bcrypt.hashpw(data.get('password').encode('utf-8'), bcrypt.gensalt())
    try:
        db.session.execute("INSERT INTO Customer (name, email, address, phone, password_hash) VALUES (:name, :email, :address, :phone, :password_hash)", 
                           {"name": name, "email": email, "address": address, "phone": phone, "password_hash": password_hash})
        db.session.commit()
        return jsonify({"message": "Customer created successfully"}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 400

# POST - Create a new order for a customer
@app.route('/customer/<int:customer_id>/orders', methods=['POST'])
def create_customer_order(customer_id):
    if request.content_type != 'application/json':
        return jsonify({"error": "Content-Type must be application/json"}), 415

    order_service_url = os.getenv('ORDER_SERVICE_URL')
    order_data = request.get_json()
    try:
        response = requests.post(f'{order_service_url}/orders', json=order_data)
        if response.status_code == 201:
            return jsonify(response.json()), 201, {'Location': f'/customer/{customer_id}/orders/{response.json()["order_id"]}'}
        else:
            return jsonify({'error': 'Failed to create order'}), 400
    except requests.exceptions.RequestException:
        return jsonify({'error': 'Failed to connect to order service'}), 500

# PUT - Update a support ticket for a customer
@app.route('/customer/<int:customer_id>/support_tickets/<int:ticket_id>', methods=['PUT'])
def update_support_ticket(customer_id, ticket_id):
    try:
        # Get the JSON data from the request
        support_ticket_data = request.get_json()
        issue = support_ticket_data.get('issue')
        status = support_ticket_data.get('status')

        # Check if the support ticket exists for the customer
        query = text("SELECT * FROM SupportTicket WHERE ticket_id = :ticket_id AND customer_id = :customer_id")
        ticket = db.session.execute(query, {"ticket_id": ticket_id, "customer_id": customer_id}).fetchone()

        if not ticket:
            return jsonify({'error': 'Support ticket not found'}), 404

        # Update the support ticket
        update_query = text("""
            UPDATE SupportTicket
            SET issue = :issue, status = :status
            WHERE ticket_id = :ticket_id AND customer_id = :customer_id
        """)
        db.session.execute(update_query, {
            "issue": issue,
            "status": status,
            "ticket_id": ticket_id,
            "customer_id": customer_id
        })
        db.session.commit()

        return jsonify({"ticket_id": ticket_id, "message": "Support ticket updated successfully"})
    except Exception as e:
        logger.error(f"Error updating support ticket: {e}")
        return jsonify({'error': 'An internal server error occurred'}), 500


# GET - Retrieve a customer's orders with query parameters (e.g., status) and pagination
@app.route('/customer/<int:customer_id>/orders', methods=['GET'])
def get_customer_orders_with_status(customer_id):
    order_service_url = os.getenv('ORDER_SERVICE_URL')
    status = request.args.get('status')
    page = request.args.get('page', 1)
    per_page = request.args.get('per_page', 10)
    
    try:
        if status:
            response = requests.get(f'{order_service_url}/orders/{customer_id}?status={status}&page={page}&per_page={per_page}')
        else:
            response = requests.get(f'{order_service_url}/orders/{customer_id}?page={page}&per_page={per_page}')
        
        if response.status_code == 200:
            return jsonify(response.json())
        else:
            return jsonify({'error': 'Orders not found'}), 404
    except requests.exceptions.RequestException:
        return jsonify({'error': 'Failed to connect to order service'}), 500

# Synchronous call to fetch customer info and orders
@app.route('/customer/<int:customer_id>/info_and_orders', methods=['GET'])
def get_customer_info_and_orders_synchronously(customer_id):
    customer_service_url = os.getenv('CUSTOMER_SERVICE_URL')
    order_service_url = os.getenv('ORDER_SERVICE_URL')
    
    try:
        customer_response = requests.get(f'{customer_service_url}/customers/{customer_id}')
        if customer_response.status_code != 200:
            return jsonify({'error': 'Customer not found'}), 404

        orders_response = requests.get(f'{order_service_url}/orders/{customer_id}')
        if orders_response.status_code != 200:
            return jsonify({'error': 'Orders not found'}), 404

        return jsonify({
            'customer': customer_response.json(),
            'orders': orders_response.json()
        })
    except requests.exceptions.RequestException:
        return jsonify({'error': 'Failed to connect to services'}), 500

# Asynchronous method to fetch customer info and orders
async def fetch_customer_info(session, customer_service_url, customer_id):
    async with session.get(f'{customer_service_url}/customers/{customer_id}') as response:
        return await response.json()

async def fetch_customer_orders(session, order_service_url, customer_id):
    async with session.get(f'{order_service_url}/orders/{customer_id}') as response:
        return await response.json()

@app.route('/customer/<int:customer_id>/async_info_and_orders', methods=['GET'])
async def get_customer_info_and_orders_asynchronously(customer_id):
    customer_service_url = os.getenv('CUSTOMER_SERVICE_URL')
    order_service_url = os.getenv('ORDER_SERVICE_URL')

    async with aiohttp.ClientSession() as session:
        customer_task = asyncio.create_task(fetch_customer_info(session, customer_service_url, customer_id))
        orders_task = asyncio.create_task(fetch_customer_orders(session, order_service_url, customer_id))

        customer_info, customer_orders = await asyncio.gather(customer_task, orders_task)

        return jsonify({
            'customer': customer_info,
            'orders': customer_orders
        })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
