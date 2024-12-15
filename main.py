import os
import time
import uuid
import logging
import requests
from dotenv import load_dotenv
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt
from functools import wraps
from flask import Flask, request, jsonify, g
from ariadne import graphql_sync, make_executable_schema, QueryType
from google.cloud import pubsub_v1  # Google Cloud Pub/Sub
from google.oauth2.service_account import Credentials
from google.auth.transport.requests import Request
from graphql import graphql_sync
from graphene import ObjectType, String, Int, List
import base64
import json

# Load environment variables
load_dotenv()

# Flask app setup
app = Flask(__name__)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

#CORS(app, expose_headers=["Authorization", "X-Grants"])
CORS(
    app,
    expose_headers=["Authorization", "X-Grants"],  # Allow client to access these headers
)

app.secret_key = os.getenv('SECRET_KEY', 'default_secret')
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'default_jwt_secret')
jwt = JWTManager(app)



# Service URLs
order_service_url = os.getenv("MICROSERVICE2_ORDER_SERVICE_URL", "").strip()
seller_service_url = os.getenv('MICROSERVICE3_SELLER_SERVICE_URL')
customer_service_url = os.getenv('MIRCROSERVICE1_CUSTOMER_SERVICE_URL')

SMART_STREET_API_URL = os.getenv('SMART_STREET_API_URL', 'https://api.smartystreets.com/street-address')
SMART_STREET_AUTH_ID = os.getenv('SMART_STREET_AUTH_ID')
SMART_STREET_AUTH_TOKEN = os.getenv('SMART_STREET_AUTH_TOKEN')
SMART_STREET_NAME = os.getenv('SMART_STREET_NAME', 'makeiteasy')

DISCORD_WEBHOOK_URL = os.getenv('DISCORD_WEBHOOK_URL')

# Load the credentials JSON from an environment variable
#credentials_json = os.getenv("GOOGLE_APPLICATION_CREDENTIALS_JSON")
credentials_json = os.getenv("GOOGLE_APPLICATION_CREDENTIALS_JSON")
if not credentials_json:
    raise Exception("Environment variable GOOGLE_APPLICATION_CREDENTIALS_JSON is not set.")

# Parse the JSON string
try:
    credentials_info = json.loads(credentials_json)
except json.JSONDecodeError as e:
    raise Exception("Invalid JSON in GOOGLE_APPLICATION_CREDENTIALS_JSON") from e

# Define the required OAuth scopes
scopes = ["https://www.googleapis.com/auth/cloud-platform"]

# Initialize the credentials object with the scopes
credentials = Credentials.from_service_account_info(credentials_info, scopes=scopes)

# Refresh the credentials to fetch an access token
auth_request = Request()
credentials.refresh(auth_request)
# Access the token for triggering workflows
access_token = credentials.token

baseurl = 'https://makeiteasy-440104.appspot.com'

# Google Cloud Pub/Sub and Workflows
GOOGLE_PUBSUB_TOPIC = os.getenv('GOOGLE_PUBSUB_TOPIC')
publisher = pubsub_v1.PublisherClient(credentials=credentials)
topic_path = "projects/makeiteasy-440104/topics/order-publishing"
GCP_WORKFLOW_URL = os.getenv('GCP_WORKFLOW_URL')


def issue_token(identity='guest'):
    """
    Function to issue a JWT token with predefined grants.
    :param identity: The identity of the user (e.g., email or username)
    :return: A dictionary with the access token and grants
    """
    try:
        # Define all available grants
        all_grants = ['create_product', 'view_customer', 'verify_address', 'create_order', 'view_order']

        # Define additional claims for the JWT token
        additional_claims = {"grants": all_grants}

        # Generate the access token
        access_token = create_access_token(identity=identity, additional_claims=additional_claims)

        # Return the token and grants
        return {
            "access_token": access_token,
            "all_grants": all_grants
        }
    except Exception as e:
        logging.error(f"Error in issue_token: {str(e)}")
        raise

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

@app.before_request
def before_request_logging():
    g.start_time = time.time()
    correlation_id = request.headers.get('X-Correlation-ID', str(uuid.uuid4()))
    g.correlation_id = correlation_id
    logger.info(f"Correlation ID: {correlation_id} - Before Request: {request.method} {request.path}")
    logger.info(f"Incoming request: {request.method} {request.path}")
    logger.info(f"Headers: {request.headers}")
    logger.info(f"Query Params: {request.args}")

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

# cusomer login
@app.route('/customer/login', methods=['POST'])
def login_customer():
    try:
        logging.info("Received login request")

        # Validate Content-Type
        if 'application/json' not in request.content_type:
            return jsonify({"error": "Unsupported Media Type", "message": "Use application/json"}), 415

        # Parse JSON payload
        data = request.get_json(silent=True)
        if not data:
            return jsonify({"error": "Invalid JSON payload"}), 400

        email = data.get('email')
        password = data.get('password')

        if not email or not password:
            logging.error("Missing email or password")
            return jsonify({"error": "Email and password are required"}), 400

        # Forward the request to the Customer Service
        logging.info("Forwarding login request to Customer Service.")
        try:
            # Log the exact URL being sent
            logging.info(f"Sending request to: {customer_service_url}/api/customers/login?email={email}&password=***")

            # Send request with query parameters
            response = requests.post(
                f"{customer_service_url}/api/customers/login",
                params={"email": email, "password": password},  # Pass as query parameters
                timeout=5
            )
        except requests.exceptions.Timeout:
            logging.error("Customer Service request timed out")
            return jsonify({"error": "Request to Customer Service timed out"}), 504

        logging.info(f"Customer Service response: {response.status_code}")

        # Handle Customer Service response
        if response.status_code == 200:
            try:
                response_data = response.json()
            except requests.exceptions.JSONDecodeError:
                logging.error("Failed to parse Customer Service response as JSON")
                response_data = {"message": response.text.strip()}

            # Issue token and grants
            try:
                logging.info("Issuing token for user")
                auth = issue_token(email)
                access_token = auth['access_token']
                all_grants = auth['all_grants']
            except Exception as e:
                logging.error(f"Failed to issue token: {str(e)}")
                return jsonify({"error": "Failed to generate access token"}), 500
            response = jsonify({
                "message": response_data.get("message", "Login successful"),
                "customer": response_data,
            })
            response.headers['Authorization'] = f"Bearer {access_token}"  # Add token to headers
            response.headers['X-Grants'] = ','.join(all_grants)  # Add grants to headers
            logger.info(response_data)
            return response, 200

        elif response.status_code == 401:
            logging.warning("Unauthorized login attempt")
            return jsonify({"error": "Invalid email or password"}), 401

        else:
            logging.error(f"Unexpected error from Customer Service: {response.text}")
            return jsonify({"error": "An unexpected error occurred. Please try again later."}), 500

    except Exception as e:
        logging.error(f"Error in login_customer: {str(e)}", exc_info=True)
        return jsonify({"error": "An internal server error occurred"}), 500

# customer register
@app.route('/customer/register', methods=['POST'])
def register_customer():
    try:
        # Log the incoming request
        logging.info("Received registration request")

        # Ensure the content type is JSON
        if request.content_type != 'application/json':
            return jsonify({"error": "Unsupported Media Type", "message": "Use application/json"}), 415

        # Parse the JSON request payload
        data = request.get_json(force=True)
        name = data.get('name')
        email = data.get('email')
        address = data.get('address')
        phone = data.get('phone')
        password = data.get('password')
        balance = data.get('balance')

        # Validate required fields
        if not all([name, email, address, phone, password, balance]):
            logging.error("Missing required fields in registration request")
            return jsonify({"error": "All fields are required"}), 400

        # Prepare the payload for the Customer Service API
        customer_service_payload = {
            "email": email,
            "name": name,
            "phone": phone,
            "password": password,
            "balance": balance,
            "address": address
        }

        # Forward the registration request to the Customer Service
        logging.info(f"Forwarding registration request to Customer Service for email: {email}")
        headers = {'Content-Type': 'application/json'}
        response = requests.post(
            f"{customer_service_url}/api/customers/register",
            json=customer_service_payload,
            headers=headers
        )

        # Log raw response
        logging.debug(f"Raw Customer Service response: {response.text}")

        # Handle the Customer Service response
        if response.status_code == 200:  # Successful registration
            try:
                response_data = response.json()
                logging.debug(f"Parsed Customer Service response: {response_data}")
            except requests.exceptions.JSONDecodeError:
                logging.error("Failed to parse Customer Service response as JSON")
                return jsonify({"error": "Invalid response from Customer Service"}), 500

            # Check if `customerId` is present
            customer_id = response_data.get("customerId")
            if not customer_id:
                logging.error("Customer ID missing in the Customer Service response")
                return jsonify({"error": "Customer ID is missing in the response"}), 500

            # Issue token and grants
            logging.info("Issuing token for user")
            auth = issue_token(email)
            access_token = auth['access_token']
            all_grants = auth['all_grants']

            # Prepare and return the response
            resp = jsonify({
                "message": "Registration successful",
                "customer": {
                    "customerId": customer_id,
                    "name": name,
                    "email": email,
                    "address": address,
                    "phone": phone,
                    "balance": balance
                }
            })
            resp.headers["Authorization"] = f"Bearer {access_token}"
            resp.headers["X-Grants"] = ','.join(all_grants)
            return resp, 201

        elif response.status_code == 400:
            logging.warning("Validation error from Customer Service")
            return jsonify({"error": response.json().get("error", "Validation error")}), 400

        elif response.status_code == 409:
            logging.warning("Conflict error from Customer Service")
            return jsonify({"error": "Account with this email already exists"}), 409

        else:
            logging.error(f"Unexpected error from Customer Service: {response.text}")
            return jsonify({"error": f"Unexpected error: {response.text}"}), response.status_code

    except Exception as e:
        # Log and handle unexpected errors
        logging.error(f"Error in register_customer: {str(e)}", exc_info=True)
        return jsonify({"error": "An internal server error occurred"}), 500

# view customer profile, this reuqires 'view_customer' grant, and jwt token
@app.route('/customer/<int:customer_id>', methods=['GET'])
@jwt_required()
@grants_required('view_customer')
def get_customer(customer_id):
    """
    Acts as an API Gateway, forwarding the request to the Customer Service and returning the response to the UI.
    """
    # Ensure the Customer Service URL is configured
    if not customer_service_url:
        return jsonify({"error": "Customer service URL is not configured"}), 500

    # Forward headers, including correlation ID and Authorization
    headers = {
        'X-Correlation-ID': g.correlation_id if hasattr(g, 'correlation_id') else None,
        'Authorization': request.headers.get('Authorization')  # Forward the JWT token
    }

    try:
        # Route the request to the Customer Service
        customer_service_endpoint = f'{customer_service_url}/api/customers/getInformationById/{customer_id}'
        logging.info(f"Forwarding request to Customer Service: {customer_service_endpoint}")
        
        response = requests.get(customer_service_endpoint, headers=headers)

        # Handle success response (200 OK)
        if response.status_code == 200:
            customer_info = response.json()

            # Add "_links" field for HATEOAS (if not already present)
            if '_links' not in customer_info:
                customer_info['_links'] = {
                    "self": {"href": request.url}  # Add a link to the current resource
                }

            logging.info(f"Customer data retrieved successfully for ID {customer_id}")
            return jsonify(customer_info), 200

        # Handle 404 (Customer not found)
        elif response.status_code == 404:
            logging.warning(f"Customer with ID {customer_id} not found.")
            return jsonify({"error": "Customer not found"}), 404

        # Handle other errors from the Customer Service
        else:
            logging.error(f"Failed to retrieve customer: {response.status_code}, {response.text}")
            return jsonify({
                "error": "Failed to retrieve customer",
                "details": response.text
            }), response.status_code

    except requests.exceptions.RequestException as e:
        # Handle network errors or connection issues
        logging.error(f"Failed to connect to Customer Service: {str(e)}")
        return jsonify({"error": "Failed to connect to Customer Service", "details": str(e)}), 500

def poll_workflow_execution(execution_name, headers, max_retries=30, sleep_time=5):
    """
    Polls the workflow execution result until it completes.
    """
    execution_url = f"https://workflowexecutions.googleapis.com/v1/{execution_name}"

    for attempt in range(max_retries):
        # Get the current execution state
        response = requests.get(execution_url, headers=headers)

        if response.status_code != 200:
            logger.error(f"Failed to fetch workflow execution status: {response.text}")
            return {"error": "Failed to fetch workflow execution status", "details": response.text}, response.status_code

        execution_data = response.json()

        # Check the execution state
        state = execution_data.get("state")
        logger.info(f"Workflow execution state: {state}")

        if state == "SUCCEEDED":
            # Return the final result of the workflow
            output = json.loads(execution_data.get("result", "{}"))
            logger.info(f"Workflow execution succeeded. Output: {output}")
            return output, 200
        elif state in ["FAILED", "CANCELLED", "TERMINATED"]:
            logger.error(f"Workflow execution failed. State: {state}, Error: {execution_data.get('error', {})}")
            return {
                "error": f"Workflow execution {state.lower()}",
                "details": execution_data.get("error", {}),
            }, 500

        # Wait before polling again
        time.sleep(sleep_time)

    # If the workflow does not complete within the maximum retries
    logger.error("Workflow execution did not complete within the maximum retries")
    return {"error": "Workflow execution timeout"}, 504

def call_step_function_workflow(order_data):
    if GCP_WORKFLOW_URL:
        try:
            # Prepare headers with the OAuth 2.0 access token
            headers = {
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json"
            }

            # Prepare the payload
            workflow_payload = {
                "argument": json.dumps({
                    "customer_id": order_data["customer_id"],
                    "status": order_data["status"],
                    "tracking_number": order_data["tracking_number"],
                    "items": order_data["items"]
                })
            }

            # Start the workflow execution
            response = requests.post(GCP_WORKFLOW_URL, json=workflow_payload, headers=headers)
            # Check if the response status code indicates success
            if response.status_code not in [200, 202]:
                logger.error(f"Workflow failed to start: {response.text}")
                return {"error": "Workflow invocation failed", "details": response.text}, response.status_code

            # Parse the workflow execution metadata
            execution_metadata = response.json()
            execution_name = execution_metadata["name"]  # Name of the execution
            logger.info(f"Workflow execution started successfully: {execution_name}")

            # Poll the execution result until the workflow completes
            execution_result = poll_workflow_execution(execution_name, headers)

            # Return the final workflow output
            return execution_result

        except Exception as e:
            logger.error(f"Workflow call error: {e}", exc_info=True)
            return {"error": "Exception occurred", "details": str(e)}, 500
    else:
        logger.error("GCP_WORKFLOW_URL is not configured")
        return {"error": "GCP_WORKFLOW_URL is not configured"}, 500

def notify_via_pubsub(event, context):
    """Triggered from a Pub/Sub topic."""
    if 'data' in event:
        try:
            # Decode the message from Base64
            message = base64.b64decode(event['data']).decode('utf-8')
            print(f"Decoded message: {message}")  # Debugging log

            # Parse JSON from the decoded message
            message_data = json.loads(message)
            print(f"Parsed message data: {message_data}")  # Debugging log

            order_id = message_data.get("order_id")

            if DISCORD_WEBHOOK_URL and order_id:
                discord_message = {
                    "content": f"Order {order_id} has been received and is being processed!"
                }
                try:
                    response = requests.post(DISCORD_WEBHOOK_URL, json=discord_message)
                    if response.status_code in [200, 204]:
                        print(f"Notification sent for order_id={order_id}")
                    else:
                        print(f"Discord webhook error: {response.status_code} - {response.text}")
                except Exception as e:
                    print(f"Error sending Discord notification: {e}")
            else:
                print("Discord Webhook URL not configured or order_id missing.")
        except json.JSONDecodeError as e:
            print(f"JSONDecodeError: {e}")
            print(f"Invalid JSON message: {message}")
        except Exception as e:
            print(f"Unexpected error: {e}")
    else:
        print("No 'data' field in event.")

##########################
# SELLER INTEGRATION
##########################

@app.route('/seller/register', methods=['POST'])
def register_seller():
    try:
        logging.info("Received seller registration request")

        # Validate Content-Type
        if request.content_type != 'application/json':
            return jsonify({"error": "Unsupported Media Type", "message": "Use application/json"}), 415

        # Parse the JSON request payload
        data = request.get_json(force=True)
        name = data.get('name')
        email = data.get('email')
        password_hash = data.get('password_hash')
        balance = data.get('balance', 0.0)
        phone_number = data.get('phone_number', '')
        address = data.get('address', '')

        # Validate required fields
        if not all([name, email, password_hash]):
            logging.error("Missing required fields in registration request")
            return jsonify({"error": "Name, email, and password are required"}), 400

        # Ensure Seller Service URL is configured
        if not seller_service_url:
            logging.error("Seller Service URL is not configured")
            return jsonify({"error": "Seller service URL is not configured"}), 500

        # Prepare the payload for the Seller Service
        seller_service_payload = {
            "name": name,
            "email": email,
            "password_hash": password_hash,
            "balance": balance,
            "phone_number": phone_number,
            "address": address
        }

        logging.info(f"Forwarding registration request to Seller Service for email: {email}")
        headers = {'Content-Type': 'application/json'}
        response = requests.post(
            f"{seller_service_url}/seller/register",
            json=seller_service_payload,
            headers=headers
        )

        logging.info(f"Seller Service Response: {response.status_code} - {response.text}")

        # Handle Seller Service response
        if response.status_code == 201:
            try:
                response_data = response.json()
            except requests.exceptions.JSONDecodeError:
                logging.error("Failed to parse Seller Service response as JSON")
                return jsonify({"error": "Invalid response from Seller Service"}), 500

            # Issue token and grants
            auth = issue_token(email)
            access_token = auth['access_token']
            all_grants = auth['all_grants']

            # Return response with token and grants
            resp = jsonify({
                "message": "Registration successful",
                "seller": response_data
            })
            resp.headers['Authorization'] = f"Bearer {access_token}"
            resp.headers['X-Grants'] = ','.join(all_grants)
            return resp, 201

        elif response.status_code == 400:
            logging.warning("Validation error from Seller Service")
            return jsonify({"error": response.json().get("error", "Validation error")}), 400

        elif response.status_code == 409:
            logging.warning("Conflict error from Seller Service")
            return jsonify({"error": "Seller with this email already exists"}), 409

        else:
            logging.error(f"Unexpected error from Seller Service: {response.text}")
            return jsonify({"error": f"Unexpected error: {response.text}"}), response.status_code

    except Exception as e:
        logging.error(f"Error in register_seller: {str(e)}", exc_info=True)
        return jsonify({"error": "An internal server error occurred"}), 500
    
@app.route('/seller/login', methods=['POST'])
def login_seller():
    try:
        logging.info("Received seller login request")

        # Validate Content-Type
        if 'application/json' not in request.content_type:
            logging.error("Invalid Content-Type")
            return jsonify({"error": "Unsupported Media Type", "message": "Use application/json"}), 415

        # Parse JSON payload
        data = request.get_json(silent=True)
        if not data:
            logging.error("Invalid JSON payload")
            return jsonify({"error": "Invalid JSON payload"}), 400

        # Extract email and password from payload
        email = data.get('email')
        password = data.get('password')

        if not email or not password:
            logging.error("Missing email or password")
            return jsonify({"error": "Email and password are required"}), 400

        # Ensure the seller service URL is configured
        if not seller_service_url:
            logging.error("Seller Service URL is not configured")
            return jsonify({"error": "Seller service URL is not configured"}), 500

        logging.info(f"Forwarding login request to Seller Service: {seller_service_url}/seller/login")

        # Forward request to the Seller Service
        response = requests.post(
            f"{seller_service_url}/seller/login",
            json={"email": email, "password": password},
            timeout=5
        )

        logging.info(f"Seller Service Response: {response.status_code} - {response.text}")

        # Handle Seller Service response
        if response.status_code == 200:
            try:
                response_data = response.json()
            except requests.exceptions.JSONDecodeError:
                logging.error("Failed to parse Seller Service response as JSON")
                return jsonify({"error": "Invalid response from Seller Service"}), 500

            # Issue token and grants
            auth = issue_token(email)
            access_token = auth['access_token']
            all_grants = auth['all_grants']

            # Return response with token and grants
            resp = jsonify({
                "message": response_data.get("message", "Login successful"),
                "seller": response_data,
            })
            resp.headers['Authorization'] = f"Bearer {access_token}"
            resp.headers['X-Grants'] = ','.join(all_grants)
            return resp, 200

        elif response.status_code == 401:
            logging.warning("Unauthorized seller login attempt")
            return jsonify({"error": "Invalid email or password"}), 401

        else:
            logging.error(f"Unexpected error from Seller Service: {response.text}")
            return jsonify({"error": "An unexpected error occurred."}), 500

    except Exception as e:
        logging.error(f"Error in login_seller: {str(e)}", exc_info=True)
        return jsonify({"error": "An internal server error occurred"}), 500

@app.route('/seller/<int:seller_id>/products', methods=['POST'])
@jwt_required()
@grants_required('create_product')
def create_seller_product(seller_id):
    if request.content_type != 'application/json':
        return jsonify({"error": "Unsupported Media Type", "message": "Use application/json"}), 415
    if not seller_service_url:
        return jsonify({"error": "Seller service URL is not configured"}), 500

    product_data = request.get_json(force=True)
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

@app.route('/composite_product/<int:product_id>', methods=['GET'])
@jwt_required()
def get_composite_product(product_id):
    if not seller_service_url:
        return jsonify({"error": "Seller service URL is not configured"}), 500
    
    headers = {
        'Authorization': request.headers.get('Authorization'),
        'X-Correlation-ID': g.correlation_id
    }

    resp = requests.get(f"{seller_service_url}/product/{product_id}", headers=headers)
    if resp.status_code == 200:
        return jsonify(resp.json()), 200
    else:
        return jsonify({"error": f"Failed to fetch product {product_id} details", "details": resp.text}), resp.status_code

##########################
# ORDER INTEGRATION
##########################

def publish_order_notification_event(order_id, customer_id=None, items=None):
    """Publish an event to the Pub/Sub topic for order notifications."""
    message = {
        "order_id": order_id,
        "customer_id": customer_id,
        "items": items
    }
    try:
        # Ensure the message is properly serialized to JSON
        future = publisher.publish(topic_path, json.dumps(message).encode("utf-8"))
        print(f"Published message to {topic_path} with ID: {future.result()}")
    except Exception as e:
        print(f"Failed to publish message to Pub/Sub topic: {e}")

# create an order
@app.route('/customer/<int:customer_id>/orders', methods=['POST'])
@jwt_required()
@grants_required('create_order')
def create_customer_order(customer_id):
    if request.content_type != 'application/json':
        return jsonify({"error": "Unsupported Media Type", "message": "Use application/json"}), 415
    if not order_service_url:
        return jsonify({"error": "Order service URL is not configured"}), 500

    order_data = request.get_json(force=True)
    order_data['customer_id'] = customer_id

    headers = {
        'Content-Type': 'application/json',
        'X-Correlation-ID': g.correlation_id,
        'Authorization': request.headers.get('Authorization')
    }
    #Composition using code and asynchronous API calls
    if 'callback_url' in order_data:
        try:
            # Log the asynchronous order creation attempt
            app.logger.info(f"Asynchronous order creation triggered for customer_id: {customer_id}")

            # Send the async request to the order service
            resp = requests.post(f'{order_service_url}/create_order/async', json=order_data, headers=headers)

            if resp.status_code == 202:
                app.logger.info("Asynchronous order creation accepted by order service")

                # Optionally trigger a step function workflow if needed
                call_step_function_workflow(None)  # Pass actual data if necessary

                # Construct response headers
                response = jsonify({"message": "Order processing accepted"})
                response.status_code = 202
                response.headers['Authorization'] = request.headers.get('Authorization', '')
                response.headers['Grants'] = request.headers.get('Grants', '')
                return response
            else:
                # Log and return error if async creation fails
                app.logger.error(f"Failed to create order asynchronously: {resp.text}")
                return jsonify({"error": "Failed to create order asynchronously", "details": resp.text}), resp.status_code

        except Exception as e:
            # Log unexpected errors during the asynchronous call
            app.logger.critical(f"Unexpected error during async order creation: {str(e)}", exc_info=True)
            return jsonify({"error": "An internal server error occurred during async order creation"}), 500

    # Composition using code and synchronous API calls
    else:
        try:
            # Log the endpoint invocation
            app.logger.debug(f"create_customer_order endpoint called for customer_id: {customer_id}")

            # Check if the Content-Type is application/json
            if request.content_type != 'application/json':
               app.logger.warning(f"Unsupported Media Type: Received Content-Type: {request.content_type}")
               return jsonify({"error": "Unsupported Media Type", "message": "Use application/json"}), 415

            # Parse the JSON payload
            try:
               order_data = request.get_json(force=True)
               app.logger.info(f"Order data received: {order_data}")
            except Exception as e:
               app.logger.warning(f"Failed to parse JSON from request body: {str(e)}", exc_info=True)
               return jsonify({"error": "Invalid JSON payload", "message": "Request body must be valid JSON"}), 400

            # Ensure `items` are included in the payload and validate their structure
            if not order_data.get("items") or not isinstance(order_data["items"], list):
               return jsonify({"error": "Invalid input", "message": "'items' field must be a list"}), 400

            # Validate that each item contains the required fields
            for item in order_data["items"]:
                if not all(key in item for key in ["product_id", "quantity", "price"]):
                   return jsonify({
                      "error": "Invalid input",
                      "message": "Each item must include 'product_id', 'quantity', and 'price'"
                    }), 400

            # Add customer_id to the payload
            order_data["customer_id"] = customer_id

            # Ensure the payload includes the required fields for the workflow
            order_data.setdefault("status", "Pending")  # Default status
            order_data.setdefault("tracking_number", "")  # Default empty tracking number

            # Log the validated order data
            app.logger.info(f"Validated order data: {order_data}")

            # Trigger Google Cloud Workflow
            workflow_response, status_code = call_step_function_workflow(order_data)

            # Handle workflow response
            if status_code not in [200, 202]:
               app.logger.error(f"Workflow invocation failed: {workflow_response.get('error')}")
               return jsonify({"error": "Workflow invocation failed", "details": workflow_response.get("error")}), 502

            # Extract the order_id from the workflow response
            order_id = workflow_response.get("order_id")
            if not order_id:
               app.logger.error("Workflow response did not contain order_id")
               return jsonify({"error": "Workflow response error", "message": "Missing order_id in response"}), 500

            # Publish an order notification event (optional)
            publish_order_notification_event(order_id, customer_id, order_data.get("items"))
            app.logger.info(f"Order notification published for order_id: {order_id}")

            # Return the workflow result as the response with headers
            response = jsonify({"message": "Order created successfully", "order_id": order_id})
            response.status_code = 201
            response.headers['Authorization'] = request.headers.get('Authorization', '')
            response.headers['Grants'] = request.headers.get('Grants', '')
            response.headers['Location'] = f"{baseurl}/customer/{customer_id}/orders/{order_id}"
            return response

        except Exception as e:
            app.logger.critical(f"Unexpected error in create_customer_order: {str(e)}", exc_info=True)
            return jsonify({"error": "An internal server error occurred"}), 500


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

# view all orders
@app.route('/customer/orders/<int:customer_id>', methods=['GET'])
@jwt_required()
@grants_required('view_order')
def get_all_orders(customer_id):
    """
    Acts as an API Gateway, forwarding a request to the Order Service to retrieve all orders for a customer.
    """
    logger.info("Starting request to get all orders for customer.")
    logger.info(f"Received request with customer_id={customer_id}")

    # Ensure the Order Service URL is configured
    if not order_service_url:
        logger.error("Order Service URL is not configured!")
        return jsonify({"error": "Order service URL is not configured"}), 500

    logger.debug(f"Order Service URL is configured: {order_service_url}")

    # Extract pagination parameters from the query string
    page = request.args.get('page', 1, type=int)  # Default to 1 if not provided
    page_size = request.args.get('page_size', 10, type=int)  # Rename per_page to page_size

    logger.info(f"Pagination parameters - page: {page}, page_size: {page_size}")

    # Set up query parameters for the Order Service request
    query_params = {
        "customer_id": customer_id,  # Add customer_id as a query parameter
        "page": page,
        "page_size": page_size
    }

    logger.info(f"Forwarding request to Order Service with params: {query_params}")

    try:
        # Forward the GET request to the Order Service
        response = requests.get(
            f"{order_service_url}/orders",
            headers={
                'Authorization': request.headers.get('Authorization'),  # Forward the JWT token
                'grants': request.headers.get('grants'),  # Forward grants
                'X-Correlation-ID': g.correlation_id if hasattr(g, 'correlation_id') else None
            },
            params=query_params  # Explicitly pass query parameters
        )

        logger.info(f"Order Service Response Status Code: {response.status_code}")
        logger.debug(f"Order Service Response Body: {response.text}")

        # Handle success response (200 OK)
        if response.status_code == 200:
            logger.info(f"Successfully retrieved orders for customer_id={customer_id}")
            orders_data = response.json()
            return jsonify(orders_data), 200

        # Handle 404 (No orders found)
        elif response.status_code == 404:
            logger.warning(f"No orders found for customer_id={customer_id}.")
            return jsonify({"error": "No orders found"}), 404

        # Handle validation errors (422) or other errors from the Order Service
        else:
            logger.error(f"Failed to retrieve orders for customer_id={customer_id}. "
                          f"Status Code: {response.status_code}, Response: {response.text}")
            return jsonify({
                "error": "Failed to retrieve orders",
                "details": response.text
            }), response.status_code

    except requests.exceptions.RequestException as e:
        # Handle network errors or connection issues
        logger.error(f"Failed to connect to Order Service for customer_id={customer_id}: {str(e)}")
        return jsonify({"error": "Failed to connect to Order Service", "details": str(e)}), 500
    
##########################
# END INTEGRATION
##########################


@app.route('/test_discord', methods=['GET'])
def test_discord():
    #trigger_end_user_notification(order_id=999)
    return jsonify({"message": "Discord notification test triggered"}), 200

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

# GraphQL Integration
query = QueryType()

@query.field("hello")
def resolve_hello(*_):
    return "Hello, GraphQL!"

schema = make_executable_schema("""
    type Query {
        hello: String!
    }
""", query)
# GraphQL Integration
@app.route('/graphql', methods=["GET", "POST"])
def graphql_server():
    if request.method == "GET":
        # Serve GraphQL Playground HTML manually
        playground_html = """
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset=utf-8/>
            <title>GraphQL Playground</title>
            <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/graphql-playground/1.7.33/static/css/index.css" />
            <link rel="shortcut icon" href="https://cdnjs.cloudflare.com/ajax/libs/graphql-playground/1.7.33/favicon.png" />
            <script src="https://cdnjs.cloudflare.com/ajax/libs/graphql-playground/1.7.33/static/js/middleware.js"></script>
        </head>
        <body>
            <div id="root"></div>
            <script>
                window.addEventListener('load', function (event) {
                    GraphQLPlayground.init(document.getElementById('root'), {
                        endpoint: '/graphql'
                    })
                })
            </script>
        </body>
        </html>
        """
        return playground_html, 200
    data = request.get_json()
    success, result = graphql_sync(schema, data, context_value=request, debug=True)
    return jsonify(result), 200 if success else 400

#######################################
# ORDER TRACKING 
#######################################

TRACKINGMORE_API_KEY = os.getenv('TRACKINGMORE_API_KEY', 'ti6225pj-2o0k-11tw-l588-w41y04dx9s4l')  # Update if needed

@app.route('/customer/<int:customer_id>/orders/<int:order_id>/tracking', methods=['GET'])
@jwt_required()
@grants_required('view_order')
def get_order_tracking(customer_id, order_id):
    # Retrieve order details from Order Service
    headers = {
        'X-Correlation-ID': g.correlation_id,
        'Authorization': request.headers.get('Authorization')
    }
    order_resp = requests.get(f'{order_service_url}/orders/{order_id}', headers=headers)
    if order_resp.status_code != 200:
        return jsonify({"error": "Failed to retrieve order details"}), order_resp.status_code

    order_info = order_resp.json()
    tracking_number = order_info.get('tracking_number')
    if not tracking_number:
        return jsonify({"error": "No tracking number available for this order"}), 404

    tm_headers = {
        'Trackingmore-Api-Key': TRACKINGMORE_API_KEY,
        'Content-Type': 'application/json'
    }

    # Attempt to create tracking in TrackingMore (if it doesn't exist)
    create_payload = {
        "tracking_number": tracking_number,
        "carrier_code": "ups"  # We specify UPS since we know it's UPS
    }
    create_resp = requests.post(
        'https://api.trackingmore.com/v2/trackings/create',
        headers=tm_headers,
        data=json.dumps(create_payload)
    )

    # If creating fails for some reason other than already existing, return error
    if create_resp.status_code not in [200, 201, 409]:
        return jsonify({"error": "Failed to create tracking", "details": create_resp.text}), create_resp.status_code

    # Now retrieve tracking details
    tm_response = requests.get(
        'https://api.trackingmore.com/v2/trackings/get',
        headers={'Trackingmore-Api-Key': TRACKINGMORE_API_KEY},
        params={'numbers': tracking_number}
    )

    if tm_response.status_code == 200:
        try:
            tm_data = tm_response.json()
            # Check if data is empty or no tracking info available
            if 'data' in tm_data and len(tm_data['data']) == 0:
                # No detailed info available yet, return direct link to TrackingMore web interface
                tracking_link = f"https://www.trackingmore.com/track/en/{tracking_number}?express=ups"
                return jsonify({"link": tracking_link}), 200
            return jsonify(tm_data), 200
        except ValueError:
            return jsonify({"error": "Invalid JSON response from TrackingMore"}), 500
    else:
        return jsonify({"error": "Failed to retrieve tracking details", "details": tm_response.text}), tm_response.status_code



#######################################
# SELLER MANAGEMENT PORTAL
#######################################
SHIPENGINE_API_KEY = os.getenv('SHIPENGINE_API_KEY', 'TEST_X/LLMqUP+3WsYMj37bImpuWcJJzP0koHzPwbbrmodz4')

@app.route('/seller_management/<int:seller_id>', methods=['GET'])
@jwt_required()
@grants_required('view_order')  
def seller_management(seller_id):

    headers = {
        'X-Correlation-ID': g.correlation_id,
        'Authorization': request.headers.get('Authorization')
    }

    seller_resp = requests.get(f'{seller_service_url}/seller/{seller_id}', headers=headers)
    if seller_resp.status_code != 200:
        return jsonify({"error": "Failed to retrieve seller details"}), seller_resp.status_code
    
    seller_info = seller_resp.json()
    seller_name = seller_info.get('name', 'Unknown')
    

    dashboard_url = f"https://dashboard.shipengine.com/?user_id={seller_id}&name={seller_name}"

    return jsonify({"seller_id": seller_id, "dashboard_url": dashboard_url}), 200

if __name__ == '__main__':
    logger.info("Starting Composite Microservice on http://0.0.0.0:8080/")
    app.run(host='0.0.0.0', port=8080)