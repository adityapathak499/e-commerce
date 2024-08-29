import pandas as pd
import sqlite3
from sqlalchemy import create_engine, Column, Integer, String, Float, Table, MetaData
from sqlalchemy.orm import sessionmaker
from sqlalchemy import select, func
from sqlalchemy.ext.declarative import declarative_base
from flask import Flask, request, jsonify
import jwt
import datetime
import bcrypt

# Database Setup
DATABASE_URI = 'sqlite:///ecommerce.db'
engine = create_engine(DATABASE_URI)
Base = declarative_base()

class Product(Base):
    __tablename__ = 'products'
    product_id = Column(Integer, primary_key=True)
    product_name = Column(String)
    category = Column(String)
    price = Column(Float)
    quantity_sold = Column(Integer)
    rating = Column(Float)
    review_count = Column(Integer)

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True)
    password_hash = Column(String)

Base.metadata.create_all(engine)
Session = sessionmaker(bind=engine)
session = Session()

# 1. Database Connection and Table Creation
def upload_data_to_db(csv_file):
    try:
        df = pd.read_csv(csv_file)

        # Verify required columns are present
        required_columns = ['price', 'quantity_sold', 'rating', 'category']
        for column in required_columns:
            if column not in df.columns:
                raise ValueError(f"Missing expected column: {column}")

        # Data Cleaning
        df['price'] = df['price'].fillna(df['price'].median())
        df['quantity_sold'] = df['quantity_sold'].fillna(df['quantity_sold'].median())
        df['rating'] = df['rating'].fillna(df.groupby('category')['rating'].transform('mean'))
        
        df.to_sql(Product.__tablename__, engine, if_exists='replace', index=False)
    except Exception as e:
        print(f"Error uploading data: {e}")

upload_data_to_db('products.csv')


app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'

@app.route('/signup', methods=['POST'])
def signup():
    try:
        data = request.get_json()
        username = data['username']
        password = data['password']
        
        if session.query(User).filter_by(username=username).first():
            return jsonify({'message': 'User already exists!'}), 409
        
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        new_user = User(username=username, password_hash=password_hash.decode('utf-8'))
        
        session.add(new_user)
        session.commit()
        return jsonify({'message': 'User created successfully!'}), 201
    except Exception as e:
        return jsonify({'message': f'Error: {e}'}), 500

@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        username = data['username']
        password = data['password']
        
        user = session.query(User).filter_by(username=username).first()
        if not user or not bcrypt.checkpw(password.encode('utf-8'), user.password_hash.encode('utf-8')):
            return jsonify({'message': 'Invalid credentials!'}), 401
        
        token = jwt.encode({
            'user_id': user.id,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
        }, app.config['SECRET_KEY'], algorithm='HS256')
        
        return jsonify({'token': token}), 200
    except Exception as e:
        return jsonify({'message': f'Error: {e}'}), 500

# 3. Summary Report
@app.route('/summary_report', methods=['GET'])
def summary_report():
    try:
        
        subquery = (
            session.query(
                Product.category,
                Product.product_name,
                (Product.price * Product.quantity_sold).label('revenue'),
                Product.quantity_sold
            ).subquery()
        )

        
        stmt = select(
            subquery.c.category,
            subquery.c.product_name,
            subquery.c.revenue,
            subquery.c.quantity_sold
        )
        
        
        with engine.connect() as connection:
            result = connection.execute(stmt)
            df = pd.DataFrame(result.fetchall(), columns=result.keys())

        
        summary = df.groupby('category').agg(
            total_revenue=pd.NamedAgg(column='revenue', aggfunc='sum'),
            top_product=pd.NamedAgg(column='product_name', aggfunc=lambda x: x.iloc[0]),
            top_product_quantity_sold=pd.NamedAgg(column='quantity_sold', aggfunc='sum')
        ).reset_index()
        
        summary.to_csv('summary_report.csv', index=False)
        return jsonify({'message': 'Summary report generated!'}), 200
    except Exception as e:
        return jsonify({'message': f'Error: {e}'}), 500

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000, debug=True)
