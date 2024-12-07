import os
import time
import uuid
import logging
import requests
from flask import Flask, jsonify, request, g
from dotenv import load_dotenv
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt
from functools import wraps

load_dotenv()

app = Flask(__name__)
CORS(app)

app.secret_key = os.getenv('SECRET_KEY', 'default_secret')
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'default_jwt_secret')
jwt = JWTManager(app)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Services
order_service_url = os.getenv('MICROSERVICE2_ORDER_SERVICE_URL', 'http://host.docker.internal:8001')
seller_service_url = os.getenv('MICROSERVICE3_SELLER_SERVICE_URL', 'http://host.docker.internal:8000')
customer_service_url = os.getenv('MICROSERVICE1_CUSTOMER_SERVICE_URL')  # Only if available

SMART_STREET_API_URL = os.getenv('SMART_STREET_API_URL', 'https://api.smartystreets.com/street-address')
SMART_STREET_AUTH_ID = os.getenv('SMART_STREET_AUTH_ID')
SMART_STREET_AUTH_TOKEN = os.getenv('SMART_STREET_AUTH_TOKEN')
# SMART_STREET_NAME not needed for direct API call, but we keep it if needed
SMART_STREET_NAME = os.getenv('SMART_STREET_NAME', 'makeiteasy')

DISCORD_WEBHOOK_URL = os.getenv('DISCORD_WEBHOOK_URL')  # set in .env if you want notifications

baseurl = 'http://127.0.0.1:8080'

@app.before_request
def before_request_logging():
    g.start_time = time.time()
    correlation_id = request.headers.get('X-Correlation-ID', str(uuid.uuid4()))
    g.correlation_id = correlation_id
    logger.info(f"Correlation ID: {correlation_id} - Before Request: {request.method} {request.path}")

@app.after_request
def after_request_logging(response):
    duration = time.time() - g.start_time
    response.headers['X-Correlation-ID'] = g.correlation_id
    return response

@app.errorhandler(400)
def bad_request(error):
    return jsonify({"error": "Bad Request", "message": str(error)}), 400

@app.errorhandler(401)
def unauthorized(error):
    return jsonify({"error": "Unauthorized", "message": str(error)}), 401

@app.errorhandler(403)
def forbidden(error):
    return jsonify({"error": "Forbidden", "message": "Insufficient grants"}), 403

@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "Not Found", "message": str(error)}), 404

@app.errorhandler(415)
def unsupported_media_type(error):
    return jsonify({"error": "Unsupported Media Type", "message": str(error)}), 415

@app.errorhandler(500)
def internal_server_error(error):
    return jsonify({"error": "Internal Server Error", "message": str(error)}), 500

@app.route('/')
def index():
    return jsonify({"message": "Composite Microservice is running!"}), 200

@app.route('/auth/token', methods=['POST'])
def issue_token():
    data = request.get_json()
    username = data.get('username', 'guest')
    grants = data.get('grants', [])
    additional_claims = {"grants": grants}
    access_token = create_access_token(identity=username, additional_claims=additional_claims)
    return jsonify({"access_token": access_token}), 200

def grants_required(required_grant):
    def decorator(fn):
        @wraps(fn)
        @jwt_required()
        def wrapper(*args, **kwargs):
            claims = get_jwt()
            user_grants = claims.get('grants', [])
            if required_grant not in user_grants:
                return jsonify({"error": "Forbidden", "message": "Insufficient grants"}), 403
            return fn(*args, **kwargs)
        return wrapper
    return decorator

##########################
# SELLER INTEGRATION     #
##########################
@app.route('/seller/register', methods=['POST'])
@jwt_required()
@grants_required('register_seller')
def register_seller():
    if request.content_type != 'application/json':
        return jsonify({"error": "Content-Type must be application/json"}), 415
    if not seller_service_url:
        return jsonify({"error": "Seller service URL is not configured"}), 500

    data = request.get_json()
    name = data.get('name')
    email = data.get('email')
    if not name or not email:
        return jsonify({"error": "Name and email are required"}), 400

    headers = {
        'Content-Type': 'application/json',
        'X-Correlation-ID': g.correlation_id,
        'Authorization': request.headers.get('Authorization')
    }

    response = requests.post(f'{seller_service_url}/seller/register', json=data, headers=headers)
    if response.status_code == 201:
        resp_json = response.json()
        seller_id = resp_json['seller']['id']
        resp = jsonify(resp_json)
        resp.status_code = 201
        resp.headers['Location'] = f"{baseurl}/seller/{seller_id}"
        return resp
    else:
        return jsonify({"error": "Failed to register seller", "details": response.text}), response.status_code

@app.route('/seller/<int:seller_id>/products', methods=['POST'])
@jwt_required()
@grants_required('create_product')
def create_seller_product(seller_id):
    if request.content_type != 'application/json':
        return jsonify({"error": "Content-Type must be application/json"}), 415
    if not seller_service_url:
        return jsonify({"error": "Seller service URL is not configured"}), 500

    product_data = request.get_json()
    product_data['seller_id'] = seller_id

    headers = {
        'Content-Type': 'application/json',
        'X-Correlation-ID': g.correlation_id,
        'Authorization': request.headers.get('Authorization')
    }

    response = requests.post(f'{seller_service_url}/product', json=product_data, headers=headers)
    if response.status_code == 201:
        resp_json = response.json()
        product_id = resp_json.get("product_id")
        if product_id:
            resp = jsonify(resp_json)
            resp.status_code = 201
            resp.headers['Location'] = f"{baseurl}/product/{product_id}"
            return resp
        else:
            return jsonify({"error": "Product ID missing in response"}), 500
    else:
        return jsonify({"error": "Failed to create product", "details": response.text}), response.status_code

##########################
# ORDER INTEGRATION      #
##########################
@app.route('/customer/<int:customer_id>/orders', methods=['POST'])
@jwt_required()
@grants_required('create_order')
def create_customer_order(customer_id):
    if request.content_type != 'application/json':
        return jsonify({"error": "Content-Type must be application/json"}), 415
    if not order_service_url:
        return jsonify({"error": "Order service URL is not configured"}), 500

    order_data = request.get_json()
    order_data['customer_id'] = customer_id

    headers = {
        'Content-Type': 'application/json',
        'X-Correlation-ID': g.correlation_id,
        'Authorization': request.headers.get('Authorization')
    }

    if 'callback_url' in order_data:
        response = requests.post(f'{order_service_url}/create_order/async', json=order_data, headers=headers)
        if response.status_code == 202:
            # If callback_url scenario: send a notification
            trigger_end_user_notification(order_id=None)
            return jsonify({"message": "Order processing accepted"}), 202
        else:
            return jsonify({"error": "Failed to create order asynchronously", "details": response.text}), response.status_code
    else:
        response = requests.post(f'{order_service_url}/create_order', json=order_data, headers=headers)
        if response.status_code == 201:
            resp_json = response.json()
            order_id = resp_json.get("order_id")
            if order_id:
                publish_order_event(order_id)
                # Automatically send Discord notification when an order is created
                trigger_end_user_notification(order_id)
                resp = jsonify(resp_json)
                resp.status_code = 201
                resp.headers['Location'] = f"{baseurl}/customer/{customer_id}/orders/{order_id}"
                return resp
            else:
                return jsonify({"error": "Order ID missing in response"}), 500
        else:
            return jsonify({"error": "Failed to create order", "details": response.text}), response.status_code

@app.route('/customer/<int:customer_id>/orders', methods=['GET'])
@jwt_required()
@grants_required('view_order')
def get_customer_orders_with_status(customer_id):
    if not order_service_url:
        return jsonify({"error": "Order service URL is not configured"}), 500

    page = request.args.get('page', 1)
    per_page = request.args.get('per_page', 10)

    headers = {
        'X-Correlation-ID': g.correlation_id,
        'Authorization': request.headers.get('Authorization')
    }

    params = {
        'customer_id': customer_id,
        'page': page,
        'page_size': per_page
    }

    response = requests.get(f'{order_service_url}/orders', headers=headers, params=params)
    if response.status_code == 200:
        orders = response.json()
        next_page = int(page) + 1
        prev_page = int(page) - 1 if int(page) > 1 else None
        links = {
            "self": {"href": f"{request.base_url}?page={page}&per_page={per_page}"},
            "next": {"href": f"{request.base_url}?page={next_page}&per_page={per_page}"}
        }
        if prev_page:
            links["prev"] = {"href": f"{request.base_url}?page={prev_page}&per_page={per_page}"}
        return jsonify({"orders": orders, "links": links}), 200
    else:
        return jsonify({'error': 'Failed to retrieve orders', 'details': response.text}), response.status_code

@app.route('/customer/<int:customer_id>/orders/<int:order_id>', methods=['GET'])
@jwt_required()
@grants_required('view_order')
def get_single_order(customer_id, order_id):
    if not order_service_url:
        return jsonify({"error": "Order service URL is not configured"}), 500

    headers = {
        'X-Correlation-ID': g.correlation_id,
        'Authorization': request.headers.get('Authorization')
    }

    response = requests.get(f'{order_service_url}/orders/{order_id}', headers=headers)
    if response.status_code == 200:
        order_info = response.json()
        if '_links' not in order_info:
            order_info['_links'] = {
                "self": {"href": request.url},
                "customer": {"href": f"{baseurl}/customer/{customer_id}"}
            }
        return jsonify(order_info), 200
    elif response.status_code == 404:
        return jsonify({'error': 'Order not found'}), 404
    else:
        return jsonify({'error': 'Failed to retrieve order', 'details': response.text}), response.status_code

@app.route('/customer/<int:customer_id>/orders/<int:order_id>/status', methods=['GET'])
@jwt_required()
@grants_required('view_order')
def get_async_order_status(customer_id, order_id):
    if not order_service_url:
        return jsonify({"error": "Order service URL is not configured"}), 500

    headers = {
        'X-Correlation-ID': g.correlation_id,
        'Authorization': request.headers.get('Authorization')
    }

    response = requests.get(f'{order_service_url}/callback/{order_id}/status', headers=headers)
    if response.status_code == 200:
        return jsonify(response.json()), 200
    elif response.status_code == 404:
        return jsonify({'error': 'Order not found'}), 404
    else:
        return jsonify({'error': 'Failed to retrieve order status', 'details': response.text}), response.status_code

def publish_order_event(order_id):
    logger.info(f"Publishing order_created event for order_id={order_id}")

def trigger_end_user_notification(order_id):
    if DISCORD_WEBHOOK_URL:
        message = {"content": f"Order has been received and is being processed! Order ID: {order_id}"}
        try:
            response = requests.post(DISCORD_WEBHOOK_URL, json=message)
            if response.status_code not in [200,204]:
                logger.error(f"Discord webhook failed with status {response.status_code}: {response.text}")
        except Exception as e:
            logger.error(f"Failed to send notification: {e}")
    else:
        logger.info("No DISCORD_WEBHOOK_URL set, skipping notification")

#############################
# CUSTOMER INTEGRATION 
# Keep this code as is 
# GPT写的框架 没连接上db 
#############################
'''
@app.route('/customer/register', methods=['POST'])
@jwt_required()
@grants_required('register_customer')
def register_customer():
    if request.content_type != 'application/json':
        return jsonify({"error": "Content-Type must be application/json"}), 415
    if not customer_service_url:
        return jsonify({"error": "Customer service URL is not configured"}), 500

    data = request.get_json()
    name = data.get('name')
    email = data.get('email')
    if not name or not email:
        return jsonify({"error": "Name and email are required"}), 400

    headers = {
        'Content-Type': 'application/json',
        'X-Correlation-ID': g.correlation_id,
        'Authorization': request.headers.get('Authorization')
    }

    response = requests.post(f'{customer_service_url}/customer/register', json=data, headers=headers)
    if response.status_code == 201:
        resp_json = response.json()
        customer_id = resp_json['customer']['id']
        resp = jsonify(resp_json)
        resp.status_code = 201
        resp.headers['Location'] = f"{baseurl}/customer/{customer_id}"
        return resp
    else:
        return jsonify({"error": "Failed to register customer", "details": response.text}), response.status_code

@app.route('/customer/<int:customer_id>', methods=['GET'])
@jwt_required()
@grants_required('view_customer')
def get_customer(customer_id):
    if not customer_service_url:
        return jsonify({"error": "Customer service URL is not configured"}), 500

    headers = {
        'X-Correlation-ID': g.correlation_id,
        'Authorization': request.headers.get('Authorization')
    }

    response = requests.get(f'{customer_service_url}/customer/{customer_id}', headers=headers)
    if response.status_code == 200:
        customer_info = response.json()
        if '_links' not in customer_info:
            customer_info['_links'] = {
                "self": {"href": request.url}
            }
        return jsonify(customer_info), 200
    elif response.status_code == 404:
        return jsonify({"error": "Customer not found"}), 404
    else:
        return jsonify({"error": "Failed to retrieve customer", "details": response.text}), response.status_code
'''

#############################
# SMART STREET INTEGRATION  #
#############################
def verify_address_with_smart_street(address_data):
    """Middleware-like function to verify address with Smart Street (SmartyStreets) via GET and query params."""
    params = {
        'auth-id': SMART_STREET_AUTH_ID,
        'auth-token': SMART_STREET_AUTH_TOKEN,
        'street': address_data.get('street'),
        'city': address_data.get('city'),
        'state': address_data.get('state')
    }
    if address_data.get('zipcode'):
        params['zipcode'] = address_data.get('zipcode')

    # No special headers needed for auth, just query params
    headers = {
        'X-Correlation-ID': g.correlation_id,
        'Authorization': request.headers.get('Authorization')
    }

    response = requests.get(SMART_STREET_API_URL, params=params, headers=headers)
    if response.status_code == 200:
        return response.json(), None
    else:
        return None, (f"Failed to verify address: {response.text}", response.status_code)

@app.route('/address/verify', methods=['POST'])
@jwt_required()
@grants_required('verify_address')
def address_verify():
    if request.content_type != 'application/json':
        return jsonify({"error": "Content-Type must be application/json"}), 415

    address_data = request.get_json()
    verified_data, error = verify_address_with_smart_street(address_data)
    if error:
        message, code = error
        return jsonify({"error": message}), code

    return jsonify(verified_data), 200

# Test Discord endpoint (just for debugging)
@app.route('/test_discord', methods=['GET'])
def test_discord():
    trigger_end_user_notification(order_id=999)
    return jsonify({"message": "Discord notification test triggered"}), 200

# CQRS with GraphQL using Graphene 3 and graphql-server beta
from graphql_server.flask import GraphQLView
from graphene import ObjectType, String, Int, List, Schema

class ProductType(ObjectType):
    product_id = Int()
    name = String()
    price = String()
    stock = Int()

class CompositeQuery(ObjectType):
    products = List(ProductType)
    def resolve_products(root, info):
        return [
            ProductType(product_id=1, name="Test Product", price="19.99", stock=50)
        ]

schema = Schema(query=CompositeQuery)
app.add_url_rule('/graphql', view_func=GraphQLView.as_view(
    'graphql', schema=schema, graphiql=True
))

if __name__ == '__main__':
    logger.info("Starting Composite Microservice on http://0.0.0.0:8080/")
    app.run(host='0.0.0.0', port=8080)
