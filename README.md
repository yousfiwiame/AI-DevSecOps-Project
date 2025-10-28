# Flask E-Commerce Application

A simple e-commerce web application built with Flask featuring user authentication, product catalog, shopping cart, and order management.

## Features

- User registration and authentication
- Product catalog with search and filtering
- Shopping cart functionality
- Order processing and checkout
- Admin panel for order management
- File upload capabilities
- REST API endpoints

## Installation

1. Clone the repository:
```bash
git clone <your-repo-url>
cd flask-ecommerce
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Run the application:
```bash
python app.py
```

The application will be available at `http://localhost:5000`

## Usage

- Register a new account or login
- Browse products and add them to cart
- Proceed to checkout to place orders
- Admin users can access the admin panel at `/admin`

## API Endpoints

- `GET /api/user/<id>` - Get user information
- `POST /api/process` - Process data
- `GET /api/search` - Search products
- `GET /api/orders` - Get orders
- `POST /api/payment/process` - Process payments
- `GET /api/export` - Export data

## Database

The application uses SQLite database (`ecommerce.db`) which is automatically created on first run with sample data.