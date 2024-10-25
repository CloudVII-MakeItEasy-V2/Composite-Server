from app import db

# Customer model corresponding to the Customer table in the database
class Customer(db.Model):
    __tablename__ = 'Customer'
    
    customer_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    address = db.Column(db.Text, nullable=False)
    phone = db.Column(db.String(15))
    password_hash = db.Column(db.String(255), nullable=False)

    # Relationship with SupportTickets
    support_tickets = db.relationship('SupportTicket', backref='customer', lazy=True)

# SupportTicket model for customer support tickets
class SupportTicket(db.Model):
    __tablename__ = 'SupportTicket'
    
    ticket_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    customer_id = db.Column(db.Integer, db.ForeignKey('Customer.customer_id'), nullable=False)
    issue = db.Column(db.Text, nullable=False)
    status = db.Column(db.Enum('Open', 'In Progress', 'Closed'), default='Open')
    created_date = db.Column(db.DateTime, default=db.func.current_timestamp())

# Order model corresponding to the Order table
class Order(db.Model):
    __tablename__ = 'Order'
    
    order_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    customer_id = db.Column(db.Integer, db.ForeignKey('Customer.customer_id'), nullable=False)
    total_amount = db.Column(db.Numeric(10, 2), nullable=False)
    status = db.Column(db.Enum('Pending', 'Shipped', 'Delivered', 'Cancelled'), default='Pending')
    created_date = db.Column(db.DateTime, default=db.func.current_timestamp())
    tracking_number = db.Column(db.String(255))

    # Relationship with OrderItems
    order_items = db.relationship('OrderItem', backref='order', lazy=True)

# OrderItem model for the items within an order
class OrderItem(db.Model):
    __tablename__ = 'OrderItem'
    
    item_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    order_id = db.Column(db.Integer, db.ForeignKey('Order.order_id'), nullable=False)
    product_id = db.Column(db.Integer, nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    price = db.Column(db.Numeric(10, 2), nullable=False)

# Payment model corresponding to the Payment table
class Payment(db.Model):
    __tablename__ = 'Payment'
    
    payment_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    order_id = db.Column(db.Integer, db.ForeignKey('Order.order_id'), nullable=False)
    payment_method = db.Column(db.Enum('Credit Card', 'PayPal'), nullable=False)
    amount = db.Column(db.Numeric(10, 2), nullable=False)
    status = db.Column(db.Enum('Pending', 'Completed', 'Refunded'), default='Pending')
    transaction_id = db.Column(db.String(255))
