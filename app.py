from flask import Flask, jsonify, request
from dotenv import load_dotenv
import os
from flask_sqlalchemy import SQLAlchemy
import requests

# Load environment variables from .env file
load_dotenv()

# Initialize Flask app
app = Flask(__name__)

# Configure the database connection using the environment variable
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
db = SQLAlchemy(app)

# Define a simple route for health check
@app.route('/')
def index():
    return jsonify({"message": "Composite Microservice is running!"})

# Route to fetch customer info from Customer Service
@app.route('/customer/<int:customer_id>', methods=['GET'])
def get_customer_info(customer_id):
    customer_service_url = os.getenv('CUSTOMER_SERVICE_URL')
    try:
        response = requests.get(f'{customer_service_url}/customers/{customer_id}')
        if response.status_code == 200:
            return jsonify(response.json())
        else:
            return jsonify({'error': 'Customer not found'}), 404
    except requests.exceptions.RequestException as e:
        return jsonify({'error': 'Failed to connect to customer service'}), 500

# Route to create an order via Order Service
@app.route('/customer/<int:customer_id>/orders', methods=['POST'])
def create_order(customer_id):
    order_service_url = os.getenv('ORDER_SERVICE_URL')
    order_data = request.get_json()  # Expecting the order details in the request body
    try:
        response = requests.post(f'{order_service_url}/orders', json=order_data)
        if response.status_code == 201:
            return jsonify(response.json()), 201
        else:
            return jsonify({'error': 'Failed to create order'}), 400
    except requests.exceptions.RequestException as e:
        return jsonify({'error': 'Failed to connect to order service'}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)

