# Flask E-commerce Application

This is a Flask-based e-commerce application that includes user authentication, data processing, and summary report generation. It uses SQLAlchemy for ORM and SQLite for database storage.

## Features

- **User Authentication**: Sign up and log in using JWT for token-based authentication.
- **Data Processing**: Upload and clean product data from a CSV file.
- **Summary Report**: Generate a summary report of sales data and save it to a CSV file.

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/adityapathak499/e-commerce.git
   cd e-commerce
   pip3 install -r requirements.txt


## API Endpoints
1. Sign Up
Endpoint: POST /signup
Description: Creates a new user account.

Request Body:

json
Copy code
{
  "username": "<username>",
  "password": "<password>"
}
Response:

Success (201): {"message": "User created successfully!"}
Conflict (409): {"message": "User already exists!"}
2. Log In
Endpoint: POST /login
Description: Authenticates a user and returns a JWT token.

Request Body:

json
Copy code
{
  "username": "<username>",
  "password": "<password>"
}
Response:

Success (200): {"token": "<jwt-token>"}
Unauthorized (401): {"message": "Invalid credentials!"}
3. Generate Summary Report
Endpoint: GET /summary_report
Description: Generates a summary report of sales data and saves it as summary_report.csv.

Response:

Success (200): {"message": "Summary report generated!"}
Error (500): If there’s an issue with generating the report, an appropriate error message will be returned.