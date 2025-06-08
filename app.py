from flask import Flask, jsonify, request, render_template, redirect, url_for, flash, session, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from datetime import datetime, timedelta
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
import os
import pandas as pd
from flask_login import login_user, logout_user, LoginManager, current_user
from flask_login import UserMixin
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
import sys
from some_data import ASSET_CLASSES, REGIONS, MARKET_TYPES, BOND_RATING, BOND_TYPES, VEHICLE
import plotly.graph_objects as go
import plotly.express as px
import json
import numpy as np
import re
from sqlalchemy.exc import IntegrityError

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///risk_management.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=30)  # Session lifetime for "remember me"
app.config['SESSION_COOKIE_SECURE'] = True  # Only send cookie over HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access to session cookie
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # CSRF protection
app.config['WTF_CSRF_ENABLED'] = True  # Enable CSRF protection

# Initialize CSRF protection
csrf = CSRFProtect(app)

# Add security headers
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'info'

# Add rate limiter
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "100 per hour"]
)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# User Model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    name = db.Column(db.String(80), nullable=False)
    password_hash = db.Column(db.String(128))
    user_type = db.Column(db.String(20), default='beginner')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    portfolios = db.relationship('Portfolio', backref='user', lazy=True)
    benchmarks = db.relationship('Benchmark', back_populates='user', lazy=True)
    funds = db.relationship('Fund', back_populates='user', lazy=True)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def is_admin(self):
        return self.user_type == 'admin'
    
    def to_dict(self):
        return {
            'id': self.id,
            'email': self.email,
            'name': self.name,
            'user_type': self.user_type,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S')
        }

# Portfolio Model
class Portfolio(db.Model):
    __tablename__ = 'portfolio'
    id = db.Column(db.Integer, primary_key=True)
    portfolio_name = db.Column(db.String(40), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    is_default = db.Column(db.Integer, nullable=False, default=0)
    paid_in = db.Column(db.Float, nullable=True, default=0.0)
    strategy_description = db.Column(db.String(500), nullable=True)
    created_at = db.Column(db.DateTime, nullable=True, default=datetime.utcnow)

    __table_args__ = (
        db.UniqueConstraint('user_id', 'portfolio_name', name='unique_user_portfolio'),
    )

    def __repr__(self):
        return f'<Portfolio {self.portfolio_name}>'

    def to_dict(self):
        return {
            'id': self.id,
            'portfolio_name': self.portfolio_name,
            'user_id': self.user_id,
            'is_default': self.is_default,
            'paid_in': self.paid_in,
            'strategy_description': self.strategy_description,
            'created_at': self.created_at.isoformat()
        }

# Holdings Model
class Holding(db.Model):
    __tablename__ = 'holding'
    id = db.Column(db.Integer, primary_key=True)
    fund_id = db.Column(db.Integer, db.ForeignKey('fund.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    portfolio_id = db.Column(db.Integer, db.ForeignKey('portfolio.id'), nullable=False)
    units = db.Column(db.Float, nullable=False, default=0.0)
    price_per_unit = db.Column(db.Float, nullable=False, default=0.0)
    use_myprice = db.Column(db.Integer, nullable=False, default=0)
    strategic_weight = db.Column(db.Float, nullable=False, default=0.0)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    # Relationships
    fund = db.relationship('Fund', backref='holdings', lazy=True)
    user = db.relationship('User', backref='holdings', lazy=True)
    portfolio = db.relationship('Portfolio', backref='holdings', lazy=True)

    def __repr__(self):
        return f'<Holding {self.fund.fund_name} in {self.portfolio.portfolio_name}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'fund_id': self.fund_id,
            'user_id': self.user_id,
            'portfolio_id': self.portfolio_id,
            'units': self.units,
            'price_per_unit': self.price_per_unit,
            'use_myprice': self.use_myprice,
            'strategic_weight': self.strategic_weight,
            'created_at': self.created_at.isoformat()
        }

# Benchmark Model for ETF benchmarks
class Benchmark(db.Model):
    __tablename__ = 'benchmark'
    id = db.Column(db.Integer, primary_key=True)
    benchmark_name = db.Column(db.String(120), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    generic_benchmark = db.Column(db.Integer, nullable=False, default=0)
    risk_factor_id = db.Column(db.Integer, db.ForeignKey('risk_factor.id'), nullable=False)
    beta = db.Column(db.Float, nullable=False, default=0.0)
    mod_duration = db.Column(db.Float, nullable=False, default=0.0)
    fx = db.Column(db.Float, nullable=False, default=0.0)
    usd = db.Column(db.Float, nullable=False, default=0.0)
    us = db.Column(db.Float, nullable=False, default=0.0)
    asset_class = db.Column(db.String(20), nullable=False)
    region = db.Column(db.String(20), nullable=False)
    developed = db.Column(db.String(20), nullable=False)
    bond_rating = db.Column(db.String(20), nullable=False)
    bond_type = db.Column(db.String(20), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    
    # Relationships
    user = db.relationship('User', back_populates='benchmarks', lazy=True)
    risk_factor = db.relationship('RiskFactor', back_populates='benchmarks', lazy=True)
    funds = db.relationship('Fund', back_populates='benchmark', lazy=True)

    def __repr__(self):
        return f'<Benchmark {self.benchmark_name}>'

    def to_dict(self):
        return {
            'id': self.id,
            'benchmark_name': self.benchmark_name,
            'user_id': self.user_id,
            'generic_benchmark': self.generic_benchmark,
            'risk_factor_id': self.risk_factor_id,
            'beta': self.beta,
            'mod_duration': self.mod_duration,
            'fx': self.fx,
            'usd': self.usd,
            'us': self.us,
            'asset_class': self.asset_class,
            'region': self.region,
            'developed': self.developed,
            'bond_rating': self.bond_rating,
            'bond_type': self.bond_type,
            'created_at': self.created_at.isoformat()
        }

# Fund Model with relationship to Benchmark
class Fund(db.Model):
    __tablename__ = 'fund'
    id = db.Column(db.Integer, primary_key=True)
    fund_name = db.Column(db.String(120), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    benchmark_id = db.Column(db.Integer, db.ForeignKey('benchmark.id'), nullable=False)
    generic_fund = db.Column(db.Integer, nullable=False, default=0)
    identifier = db.Column(db.String(50), nullable=False)
    long_name = db.Column(db.String(200), nullable=False)
    one_word_name = db.Column(db.String(20), nullable=False)
    price = db.Column(db.Float, nullable=True)
    date = db.Column(db.Date, nullable=True)
    ticker = db.Column(db.String(20), nullable=True)
    vehicle = db.Column(db.Integer, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    # Relationships
    user = db.relationship('User', back_populates='funds', lazy=True)
    benchmark = db.relationship('Benchmark', back_populates='funds', lazy=True)

    def __repr__(self):
        return f'<Fund {self.fund_name}>'

    def to_dict(self):
        return {
            'id': self.id,
            'fund_name': self.fund_name,
            'user_id': self.user_id,
            'benchmark_id': self.benchmark_id,
            'generic_fund': self.generic_fund,
            'identifier': self.identifier,
            'long_name': self.long_name,
            'one_word_name': self.one_word_name,
            'price': self.price,
            'date': self.date.isoformat() if self.date else None,
            'ticker': self.ticker,
            'vehicle': self.vehicle,
            'created_at': self.created_at.isoformat()
        }

# Risk Factor Model
class RiskFactor(db.Model):
    __tablename__ = 'risk_factor'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False, unique=True)
    description = db.Column(db.Text, nullable=True)
    asset_class = db.Column(db.String(20), nullable=False, default='Other')
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    
    # Relationships
    data = db.relationship('RiskFactorData', backref='risk_factor', lazy=True)
    benchmarks = db.relationship('Benchmark', back_populates='risk_factor', lazy=True)

    def __repr__(self):
        return f'<RiskFactor {self.name}>'

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'asset_class': self.asset_class,
            'created_at': self.created_at.isoformat()
        }

# Risk Factor Data Model
class RiskFactorData(db.Model):
    __tablename__ = 'risk_factor_data'
    id = db.Column(db.Integer, primary_key=True)
    risk_factor_id = db.Column(db.Integer, db.ForeignKey('risk_factor.id'), nullable=False)
    date = db.Column(db.Date, nullable=False)
    daily_return = db.Column(db.Float, nullable=False)
    
    __table_args__ = (
        db.UniqueConstraint('risk_factor_id', 'date', name='unique_risk_factor_date'),
    )

    def __repr__(self):
        return f'<RiskFactorData {self.risk_factor.name} {self.date}>'

    def to_dict(self):
        return {
            'id': self.id,
            'risk_factor_id': self.risk_factor_id,
            'date': self.date.isoformat(),
            'daily_return': self.daily_return
        }

# Login decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


# Routes
@app.route('/', methods=['GET', 'POST'])
def home():
    if current_user.is_authenticated:
        return redirect(url_for('get_portfolios'))
    return redirect(url_for('register'))



@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")  # Rate limit login attempts
def login():
    if current_user.is_authenticated:
        return redirect(url_for('get_portfolios'))
        
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        remember = request.form.get('remember') == 'on'
        
        # Basic validation
        if not email or not password:
            return render_template('login.html', error='Email and password are required')
        
        try:
            user = User.query.filter_by(email=email).first()
            
            # Check if user exists and password is correct
            if user is None or not user.check_password(password):
                # Log failed attempt in database
                failed_attempt = LoginAttempt(
                    email=email,
                    ip_address=request.remote_addr,
                    timestamp=datetime.utcnow()
                )
                db.session.add(failed_attempt)
                db.session.commit()
                
                # Check for too many failed attempts
                recent_attempts = LoginAttempt.query.filter(
                    LoginAttempt.email == email,
                    LoginAttempt.ip_address == request.remote_addr,
                    LoginAttempt.timestamp > datetime.utcnow() - timedelta(minutes=15)
                ).count()
                
                if recent_attempts >= 5:
                    return render_template('login.html', error='Too many failed attempts. Please try again later.')
                
                return render_template('login.html', error='Invalid email or password')
            
            # Set remember me duration
            remember_duration = timedelta(days=30) if remember else timedelta(hours=1)
            
            # Login user
            login_user(user, remember=remember, duration=remember_duration)
            
            # Set session as permanent if remember me is checked
            if remember:
                session.permanent = True
            
            # Clear any failed attempts for this user
            LoginAttempt.query.filter_by(email=email).delete()
            db.session.commit()
            
            # Redirect to next page if specified
            next_page = request.args.get('next')
            if not next_page or not next_page.startswith('/'):
                next_page = url_for('get_portfolios')
            
            return redirect(next_page)
            
        except Exception as e:
            db.session.rollback()
            return render_template('login.html', error='An error occurred during login. Please try again.')
    
    return render_template('login.html')

@app.route('/user_page')
@login_required
def user_page():
    return render_template('user_profile.html', user=current_user)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/users')
def get_users():
    users = User.query.all()
    return render_template('users.html', users=users)

@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    if request.method == 'POST':
        form_type = request.form.get('form_type')
        
        try:
            if form_type == 'name':
                name = request.form.get('name')
                if name:
                    current_user.name = name
                    db.session.commit()
                    return render_template('edit_profile.html', user=current_user, success='Name updated successfully')
                
            elif form_type == 'email':
                current_password = request.form.get('current_password')
                if not current_user.check_password(current_password):
                    return render_template('edit_profile.html', user=current_user, error='Current password is incorrect')
                
                email = request.form.get('email')
                if email and email != current_user.email:
                    if User.query.filter_by(email=email).first() is not None:
                        return render_template('edit_profile.html', user=current_user, error='Email already in use')
                    current_user.email = email
                    db.session.commit()
                    return render_template('edit_profile.html', user=current_user, success='Email updated successfully')
                
            elif form_type == 'password':
                current_password = request.form.get('current_password')
                if not current_user.check_password(current_password):
                    return render_template('edit_profile.html', user=current_user, error='Current password is incorrect')
                
                new_password = request.form.get('new_password')
                confirm_password = request.form.get('confirm_password')
                
                if not new_password or not confirm_password:
                    return render_template('edit_profile.html', user=current_user, error='New password and confirmation are required')
                
                if new_password != confirm_password:
                    return render_template('edit_profile.html', user=current_user, error='New passwords do not match')
                
                current_user.set_password(new_password)
                db.session.commit()
                return render_template('edit_profile.html', user=current_user, success='Password updated successfully')
            
        except Exception as e:
            db.session.rollback()
            return render_template('edit_profile.html', user=current_user, error=str(e))
    
    return render_template('edit_profile.html', user=current_user)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('get_portfolios'))
        
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        # Basic validation
        if not email or not password or not confirm_password:
            return render_template('register.html', error='All fields are required')
        
        # Password confirmation check
        if password != confirm_password:
            return render_template('register.html', error='Passwords do not match')
        
        # Password strength validation
        if len(password) < 8:
            return render_template('register.html', error='Password must be at least 8 characters long')
        
        # Email format validation
        if not '@' in email or not '.' in email:
            return render_template('register.html', error='Invalid email format')
        
        # Check for existing email
        if User.query.filter_by(email=email).first() is not None:
            return render_template('register.html', error='Email already exists')
        
        try:
            # Start transaction
            db.session.begin_nested()
            
            # Create user
            user = User(
                email=email,
                name=email.split('@')[0],  # Set name to the part before @ in email
                user_type='beginner'
            )
            user.set_password(password)
            db.session.add(user)
            db.session.flush()  # This gets us the user.id
            
            # Create 3 portfolios
            default_portfolio = Portfolio(
                portfolio_name="Long Run Portfolio",
                user_id=user.id,
                is_default=1
            )
            portfolio1 = Portfolio(
                portfolio_name="Emergency Fund",
                user_id=user.id,
                is_default=0
            )
            portfolio2 = Portfolio(
                portfolio_name="Other Investments",
                user_id=user.id,
                is_default=0
            )
            db.session.add(default_portfolio)
            db.session.add(portfolio1)
            db.session.add(portfolio2)
            # Commit transaction
            db.session.commit()
            
            # Log in the user automatically
            login_user(user)
            return redirect(url_for('get_portfolios'))
            
        except Exception as e:
            # Rollback transaction on error
            db.session.rollback()
            return render_template('register.html', error='An error occurred during registration. Please try again.')
    
    return render_template('register.html')

@app.route('/admin')
@login_required
def admin_dashboard():
    if not current_user.is_admin():
        flash('You do not have access to the admin dashboard.', 'error')
        return redirect(url_for('home'))
    return render_template('admin_dashboard.html')



@app.route('/get_benchmarks')
@login_required
def get_benchmarks():
    benchmarks = Benchmark.query.filter(
        (Benchmark.generic_benchmark == 1) |  # Show all generic benchmarks
        (Benchmark.user_id == current_user.id)  # Show user's own benchmarks
    ).order_by(Benchmark.generic_benchmark, Benchmark.asset_class, Benchmark.benchmark_name).all()
    return render_template('benchmarks.html', benchmarks=benchmarks, asset_classes=ASSET_CLASSES)

@app.route('/new_benchmark', methods=['GET', 'POST'])
@login_required
def new_benchmark():
    # Load risk factors once at the beginning
    risk_factors = RiskFactor.query.all()
    
    # Prepare form options
    form_options = {
        'asset_classes': ASSET_CLASSES,
        'regions': REGIONS,
        'market_types': MARKET_TYPES,
        'bond_ratings': BOND_RATING,
        'bond_types': BOND_TYPES,
        'vehicles': VEHICLE
    }
    
    if request.method == 'POST':
        # Get form data and strip whitespace
        benchmark_name = request.form.get('benchmark_name', '').strip()
        risk_factor_id = request.form.get('risk_factor_id', '').strip()
        asset_class = request.form.get('asset_class', '').strip()
        region = request.form.get('region', '').strip()
        developed = request.form.get('developed', '').strip()
        
        # Handle generic_benchmark field first
        if current_user.is_admin():
            generic_benchmark = request.form.get('generic_benchmark', '0')
            try:
                generic_benchmark = int(generic_benchmark)
                if generic_benchmark not in [0, 1]:
                    flash('Invalid benchmark type selected', 'error')
                    return render_template('new_benchmark.html', 
                                        risk_factors=risk_factors,
                                        form_options=form_options)
            except ValueError:
                flash('Invalid benchmark type value', 'error')
                return render_template('new_benchmark.html', 
                                    risk_factors=risk_factors,
                                    form_options=form_options)
        else:
            generic_benchmark = 0  # Regular users can only create user-specific benchmarks
        
        # Validate required fields
        required_fields = {
            'benchmark_name': benchmark_name,
            'risk_factor_id': risk_factor_id,
            'asset_class': asset_class,
            'region': region,
            'developed': developed
        }
        
        for field, value in required_fields.items():
            if not value:
                flash(f'{field.replace("_", " ").title()} is required', 'error')
                return render_template('new_benchmark.html', 
                                    risk_factors=risk_factors,
                                    form_options=form_options)
        
        # Validate numeric fields
        numeric_fields = {
            'beta': request.form.get('beta'),
            'mod_duration': request.form.get('mod_duration'),
            'fx': request.form.get('fx'),
            'usd': request.form.get('usd'),
            'us': request.form.get('us')
        }
        
        numeric_values = {}
        for field, value in numeric_fields.items():
            if value:
                try:
                    numeric_values[field] = float(value)
                except ValueError:
                    flash(f'Invalid value for {field}. Please enter a valid number.', 'error')
                    return render_template('new_benchmark.html', 
                                        risk_factors=risk_factors,
                                        form_options=form_options)
            else:
                numeric_values[field] = None
        
        try:
            # Create new benchmark
            new_benchmark = Benchmark(
                benchmark_name=benchmark_name,
                user_id=current_user.id,
                generic_benchmark=generic_benchmark,
                risk_factor_id=risk_factor_id,
                beta=numeric_values['beta'],
                mod_duration=numeric_values['mod_duration'],
                fx=numeric_values['fx'],
                usd=numeric_values['usd'],
                us=numeric_values['us'],
                asset_class=asset_class,
                region=region,
                developed=developed,
                bond_rating=request.form.get('bond_rating'),
                bond_type=request.form.get('bond_type')
            )
            
            db.session.add(new_benchmark)
            db.session.commit()
            flash('Benchmark created successfully!', 'success')
            return redirect(url_for('get_benchmarks'))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Error creating benchmark: {str(e)}', 'error')
            return render_template('new_benchmark.html', 
                                risk_factors=risk_factors,
                                form_options=form_options)
    
    return render_template('new_benchmark.html', 
                         risk_factors=risk_factors,
                         form_options=form_options)

@app.route('/delete_benchmark/<int:id>', methods=['POST'])
@login_required
def delete_benchmark(id):
    benchmark = Benchmark.query.get_or_404(id)
    
    # Check if user has permission to delete
    if not current_user.is_admin() and benchmark.user_id != current_user.id:
        flash('You do not have permission to delete this benchmark', 'error')
        return redirect(url_for('get_benchmarks'))
    
    # Check if benchmark has any related funds
    related_funds = Fund.query.filter_by(benchmark_id=id).all()
    if related_funds:
        fund_list = [f"• {fund.fund_name}" for fund in related_funds]
        error_message = "This benchmark is currently assigned to the following funds:\n"
        error_message += "\n".join(fund_list)
        error_message += "\n\nPlease delete these funds first before deleting this benchmark."
        flash(error_message, 'error')
        return redirect(url_for('get_benchmarks'))
    
    try:
        # Additional check to ensure we're not deleting a generic benchmark unless admin
        if benchmark.generic_benchmark and not current_user.is_admin():
            flash('You do not have permission to delete generic benchmarks', 'error')
            return redirect(url_for('get_benchmarks'))
            
        db.session.delete(benchmark)
        db.session.commit()
        flash('Benchmark was successfully deleted', 'success')
        return redirect(url_for('get_benchmarks'))
    except Exception as e:
        db.session.rollback()
        flash(f'An error occurred while deleting the benchmark: {str(e)}', 'error')
        return redirect(url_for('get_benchmarks'))

# Fund routes
@app.route('/get_funds')
@login_required
def get_funds():

    funds = Fund.query \
    .filter((Fund.generic_fund == 1) | (Fund.user_id == current_user.id)) \
    .join(Benchmark, Fund.benchmark_id == Benchmark.id, isouter=True) \
    .order_by(Fund.generic_fund, Benchmark.asset_class, Fund.fund_name) \
    .all()


    # Get user's portfolios for the dropdown
    portfolios = Portfolio.query.filter_by(user_id=current_user.id).order_by(Portfolio.portfolio_name).all()
    
    return render_template('funds.html', 
                         funds=funds,
                         portfolios=portfolios,
                         asset_classes=ASSET_CLASSES)

@app.route('/new_fund', methods=['GET', 'POST'])
@login_required
def new_fund():
    # Load benchmarks
    benchmarks = Benchmark.query.filter(
        (Benchmark.generic_benchmark == 1) | 
        (Benchmark.user_id == current_user.id)
    ).all()

    if request.method == 'POST':
        try:
            # Get form data and strip whitespace
            fund_name = request.form.get('fund_name', '').strip()
            long_name = request.form.get('long_name', '').strip()
            one_word_name = request.form.get('one_word_name', '').strip()
            ticker = request.form.get('ticker', '').strip()
            identifier = request.form.get('identifier', '').strip()
            vehicle = request.form.get('vehicle', '').strip()
            benchmark_id = request.form.get('benchmark_id', '').strip()
            
            # Handle generic_fund field
            if current_user.is_admin():
                generic_fund = request.form.get('generic_fund', '0')
                if generic_fund not in ['0', '1']:
                    flash('Invalid fund type selected.', 'error')
                    return render_template('new_fund.html', benchmarks=benchmarks, vehicles=VEHICLE)
            else:
                generic_fund = '0'  # Non-admin users can only create user-specific funds

            # Validate required fields
            required_fields = {
                'fund_name': fund_name,
                'long_name': long_name,
                'one_word_name': one_word_name,
                'ticker': ticker,
                'identifier': identifier,
                'vehicle': vehicle,
                'benchmark_id': benchmark_id
            }
            
            for field, value in required_fields.items():
                if not value:
                    flash(f'{field.replace("_", " ").title()} is required.', 'error')
                    return render_template('new_fund.html', benchmarks=benchmarks, vehicles=VEHICLE)

            # Create new fund
            new_fund = Fund(
                fund_name=fund_name,
                long_name=long_name,
                one_word_name=one_word_name,
                ticker=ticker,
                identifier=identifier,
                vehicle=vehicle,
                benchmark_id=benchmark_id,
                user_id=current_user.id,
                generic_fund=int(generic_fund)
            )

            db.session.add(new_fund)
            db.session.commit()
            flash('Fund created successfully!', 'success')
            return redirect(url_for('get_funds'))

        except Exception as e:
            db.session.rollback()
            flash(f'Error creating fund: {str(e)}', 'error')
            return render_template('new_fund.html', benchmarks=benchmarks, vehicles=VEHICLE)

    return render_template('new_fund.html', benchmarks=benchmarks, vehicles=VEHICLE)

@app.route('/delete_fund/<int:id>', methods=['POST'])
@login_required
def delete_fund(id):
    fund = Fund.query.get_or_404(id)
    
    # Check if user has permission to delete
    if not current_user.is_admin() and fund.user_id != current_user.id:
        flash('You do not have permission to delete this fund', 'error')
        return redirect(url_for('get_funds'))
    
    # Check if fund has any related holdings
    related_holdings = Holding.query.filter_by(fund_id=id).all()
    if related_holdings:
        portfolio_list = []
        for holding in related_holdings:
            portfolio_name = holding.portfolio.portfolio_name if holding.portfolio else 'Unknown Portfolio'
            portfolio_list.append(f"• {portfolio_name}")
        
        error_message = "This fund is currently assigned to the following portfolios:\n"
        error_message += "\n".join(portfolio_list)
        error_message += "\n\nPlease remove this fund from these portfolios first before deleting it."
        flash(error_message, 'error')
        return redirect(url_for('get_funds'))
    
    try:
        # Additional check to ensure we're not deleting a generic fund unless admin
        if fund.generic_fund and not current_user.is_admin():
            flash('You do not have permission to delete generic funds', 'error')
            return redirect(url_for('get_funds'))
            
        db.session.delete(fund)
        db.session.commit()
        flash('Fund was successfully deleted', 'success')
        return redirect(url_for('get_funds'))
    except Exception as e:
        db.session.rollback()
        flash(f'An error occurred while deleting the fund: {str(e)}', 'error')
        return redirect(url_for('get_funds'))

# Risk Factor routes
@app.route('/get_risk_factors')
@login_required
def get_risk_factors():
    if not current_user.is_admin():
        flash('You do not have permission to access this page.', 'error')
        return redirect(url_for('home'))
    risk_factors = RiskFactor.query.order_by(RiskFactor.asset_class, RiskFactor.name).all()
    return render_template('risk_factors.html', risk_factors=risk_factors, asset_classes=ASSET_CLASSES)

@app.route('/new_risk_factor', methods=['GET', 'POST'])
@login_required
def new_risk_factor():
    if not current_user.is_admin():
        flash('You do not have permission to access this page.', 'error')
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        description = request.form.get('description', '').strip()
        asset_class = request.form.get('asset_class', 'Other')
        
        # Validate name
        if not name:
            return render_template('new_risk_factor.html', error='Name is required')
        
        if len(name) > 120:
            return render_template('new_risk_factor.html', error='Name must be 120 characters or less')
        
        # Check for duplicate name
        if RiskFactor.query.filter_by(name=name).first() is not None:
            return render_template('new_risk_factor.html', error='A risk factor with that name already exists')
        
        try:
            risk_factor = RiskFactor(
                name=name,
                description=description if description else None,  # Store None if empty string
                asset_class=asset_class
            )
            db.session.add(risk_factor)
            db.session.commit()
            flash('Risk factor created successfully', 'success')
            return redirect(url_for('get_risk_factors'))
        except Exception as e:
            db.session.rollback()
            return render_template('new_risk_factor.html', error='An error occurred while creating the risk factor')
    
    return render_template('new_risk_factor.html')

@app.route('/risk_factor/<int:id>')
@login_required
def view_risk_factor(id):
    if not current_user.is_admin():
        flash('You do not have permission to access this page.', 'error')
        return redirect(url_for('home'))
        
    risk_factor = RiskFactor.query.get_or_404(id)
    data = RiskFactorData.query.filter_by(risk_factor_id=id).order_by(RiskFactorData.date).all()
    
    # If no data exists, return template without plot
    if not data:
        return render_template('view_risk_factor.html',
                             risk_factor=risk_factor, 
                             data=data,
                             plot_json=None)
    
    # Prepare data for cumulative returns calculation
    dates = [d.date.strftime('%Y-%m-%d') for d in data]
    returns = [float(d.daily_return)/100 for d in data]  # Convert percentage to decimal
    
    # Calculate cumulative returns by accumulating the product
    cumulative_returns = []
    cumulative_return = 1.0  # Start with 1 (100%)
    
    for ret in returns:
        cumulative_return *= (1 + ret)  # Multiply by (1 + return) for each day
        cumulative_returns.append(cumulative_return - 1)  # Convert to return percentage
    
    # Convert to percentage for display
    cumulative_returns_pct = [r * 100 for r in cumulative_returns]
    
    # Create enhanced plotly figure
    fig = go.Figure()
    
    # Add trace with cumulative returns
    fig.add_trace(go.Scatter(
        x=dates,
        y=cumulative_returns_pct,
        mode='lines+markers',  # Add markers for hover effect
        name='Cumulative Return',
        line=dict(
            color='#2E5BFF',
            width=2
        ),
        marker=dict(
            size=6,
            color='#2E5BFF',
            opacity=0,  # Hide markers by default
            line=dict(
                color='white',
                width=1
            )
        ),
        fill='tonexty',
        fillcolor='rgba(46, 91, 255, 0.1)',
        hovertemplate='%{x}<br>Return: %{y:.2f}%<extra></extra>'  # Added date back to hover template
    ))
    
    # Enhanced layout
    fig.update_layout(
        showlegend=False,
        margin=dict(l=40, r=40, t=20, b=40),
        plot_bgcolor='white',
        paper_bgcolor='white',
        xaxis=dict(
            showgrid=False,  # Remove grid
            showline=True,
            linecolor='rgba(0,0,0,0.2)',
            linewidth=1,
            title=dict(
                text='Date',
                font=dict(
                    family='Inter',
                    size=12,
                    color='rgba(0,0,0,0.6)'
                )
            ),
            tickfont=dict(
                family='Inter',
                size=10,
                color='rgba(0,0,0,0.6)'
            )
        ),
        yaxis=dict(
            showgrid=False,  # Remove grid
            showline=True,
            linecolor='rgba(0,0,0,0.2)',
            linewidth=1,
            title=dict(
                text='Cumulative Return',
                font=dict(
                    family='Inter',
                    size=12,
                    color='rgba(0,0,0,0.6)'
                )
            ),
            ticksuffix='%',
            tickfont=dict(
                family='Inter',
                size=10,
                color='rgba(0,0,0,0.6)'
            ),
            zeroline=False,  # Remove zero line
            range=[min(cumulative_returns_pct) * 1.1, max(cumulative_returns_pct) * 1.1]
        ),
        # Hover configuration
        hovermode='closest',  # Show hover only near points
        hoverlabel=dict(
            bgcolor='white',
            font_size=12,
            font_family="Inter"
        ),
        # Add subtle animations
        transition_duration=500,
        transition=dict(
            duration=500,
            easing='cubic-in-out'
        ),
        # Hover effects
        hoverdistance=50,
        spikedistance=-1  # Disable spike lines
    )
    
    # Convert the figure to JSON for frontend
    plot_json = fig.to_json()
    
    return render_template('view_risk_factor.html',
                         risk_factor=risk_factor, 
                         data=data,
                         plot_json=plot_json)

@app.route('/risk_factor/<int:id>/upload_data', methods=['GET', 'POST'])
@login_required
def upload_risk_factor_data(id):
    if not current_user.is_admin():
        flash('You do not have permission to access this page.', 'error')
        return redirect(url_for('home'))
        
    risk_factor = RiskFactor.query.get_or_404(id)
    
    if request.method == 'POST':
        if 'file' not in request.files:
            return render_template('upload_risk_factor_data.html', 
                                risk_factor=risk_factor,
                                error='No file uploaded')
        
        file = request.files['file']
        if file.filename == '':
            return render_template('upload_risk_factor_data.html', 
                                risk_factor=risk_factor,
                                error='No file selected')
        
        if file and file.filename.endswith('.csv'):
            try:
                # Read CSV file
                df = pd.read_csv(file)
                
                # Validate columns
                required_columns = ['date', 'daily_return']
                if not all(col in df.columns for col in required_columns):
                    return render_template('upload_risk_factor_data.html',
                                        risk_factor=risk_factor,
                                        error='CSV must contain date and daily_return columns')
                
                # Convert date strings to datetime
                df['date'] = pd.to_datetime(df['date'])
                
                # Delete existing data for this risk factor
                RiskFactorData.query.filter_by(risk_factor_id=id).delete()
                
                # Insert new data
                for _, row in df.iterrows():
                    data_point = RiskFactorData(
                        risk_factor_id=id,
                        date=row['date'].date(),
                        daily_return=float(row['daily_return'])
                    )
                    db.session.add(data_point)
                
                db.session.commit()
                return redirect(url_for('view_risk_factor', id=id))
            
            except Exception as e:
                db.session.rollback()
                return render_template('upload_risk_factor_data.html',
                                    risk_factor=risk_factor,
                                    error=f'Error processing file: {str(e)}')
        else:
            return render_template('upload_risk_factor_data.html',
                                risk_factor=risk_factor,
                                error='Please upload a CSV file')
    
    return render_template('upload_risk_factor_data.html', risk_factor=risk_factor)

@app.route('/delete_risk_factor/<int:id>', methods=['POST'])
@login_required
def delete_risk_factor(id):
    if not current_user.is_admin():
        flash('You do not have permission to delete risk factors', 'error')
        return redirect(url_for('get_risk_factors'))
    
    risk_factor = RiskFactor.query.get_or_404(id)
    
    # Check if risk factor has any related benchmarks
    related_benchmarks = Benchmark.query.filter_by(risk_factor_id=id).all()
    if related_benchmarks:
        benchmark_list = [f"• {benchmark.benchmark_name}" for benchmark in related_benchmarks]
        error_message = "This risk factor is currently assigned to the following benchmarks:\n"
        error_message += "\n".join(benchmark_list)
        error_message += "\n\nPlease delete these benchmarks first before deleting this risk factor."
        flash(error_message, 'error')
        return redirect(url_for('get_risk_factors'))
    
    try:
        db.session.delete(risk_factor)
        db.session.commit()
        flash('Risk factor was successfully deleted', 'success')
        return redirect(url_for('get_risk_factors'))
    except Exception as e:
        db.session.rollback()
        flash(f'An error occurred while deleting the risk factor: {str(e)}', 'error')
        return redirect(url_for('get_risk_factors'))

# Portfolio routes
@app.route('/portfolios')
@login_required
def get_portfolios():
    portfolios = Portfolio.query.filter_by(user_id=current_user.id).order_by(Portfolio.is_default.desc(), Portfolio.portfolio_name).all()
    return render_template('portfolios.html', portfolios=portfolios)

@app.route('/new_portfolio', methods=['GET', 'POST'])
@login_required
def new_portfolio():
    if request.method == 'POST':
        portfolio_name = request.form.get('portfolio_name', '').strip()
        strategy_description = request.form.get('strategy_description', '').strip()
        
        # Validate portfolio name
        if not portfolio_name:
            return render_template('new_portfolio.html', error='Portfolio name is required')
            
        if len(portfolio_name) > 40:
            return render_template('new_portfolio.html', error='Portfolio name must be 40 characters or less')
            
        # Validate portfolio name characters
        if not re.match(r'^[a-zA-Z0-9\s\-_\.]+$', portfolio_name):
            return render_template('new_portfolio.html', 
                error='Portfolio name can only contain letters, numbers, spaces, hyphens, underscores, and dots')
        
        # Validate strategy description length if provided
        if strategy_description and len(strategy_description) > 500:
            return render_template('new_portfolio.html', 
                error='Strategy description must be 500 characters or less')
        
        # Check if user already has a portfolio with this name
        existing_portfolio = Portfolio.query.filter_by(
            user_id=current_user.id,
            portfolio_name=portfolio_name
        ).first()
        
        if existing_portfolio:
            return render_template('new_portfolio.html', 
                error='You already have a portfolio with this name')
            
        try:
            # Start transaction
            db.session.begin_nested()
            
            new_portfolio = Portfolio(
                portfolio_name=portfolio_name,
                user_id=current_user.id,
                is_default=0,  # Explicitly set to 0 (not default portfolio)
                paid_in=0.0,   # Explicitly set to 0.0
                strategy_description=strategy_description if strategy_description else None,
                created_at=datetime.utcnow()  # Explicitly set creation time
            )
            
            # Validate the portfolio object
            if not all([
                new_portfolio.portfolio_name,
                new_portfolio.user_id,
                isinstance(new_portfolio.is_default, int),
                isinstance(new_portfolio.paid_in, float),
                new_portfolio.created_at
            ]):
                raise ValueError("Invalid portfolio data")
            
            db.session.add(new_portfolio)
            db.session.commit()
            flash('Portfolio created successfully!', 'success')
            return redirect(url_for('get_portfolios'))
            
        except ValueError as ve:
            db.session.rollback()
            flash('Invalid portfolio data. Please check your input.', 'error')
            return render_template('new_portfolio.html', error=str(ve))
        except IntegrityError:
            db.session.rollback()
            flash('A portfolio with this name already exists.', 'error')
            return render_template('new_portfolio.html', 
                error='You already have a portfolio with this name')
        except Exception as e:
            db.session.rollback()
            app.logger.error(f'Error creating portfolio: {str(e)}')
            flash('An error occurred while creating the portfolio. Please try again.', 'error')
            return render_template('new_portfolio.html', 
                error='An unexpected error occurred. Please try again.')
    
    return render_template('new_portfolio.html')

@app.route('/view_portfolio/<int:id>')
@login_required
def view_portfolio(id):
    from some_data import ASSET_CLASSES
    
    portfolio = Portfolio.query.filter_by(id=id, user_id=current_user.id).first_or_404()
    
    # Get holdings with their fund and benchmark data
    holdings = Holding.query.filter_by(portfolio_id=id).join(Holding.fund).order_by(Fund.fund_name).all()
    
    # Initialize dictionaries for tracking
    asset_class_sums = {}
    asset_class_strategic_sums = {}  # New dictionary for strategic weight sums
    asset_class_diff_sums = {}  # New dictionary for difference sums
    asset_class_weight_diffs = {}  # New dictionary for weight differences
    holdings_by_asset_class = {}
    total_portfolio_value = 0.0
    total_weight = 0.0
    total_strategic_weight = 0.0  # New variable for total strategic weight
    total_diff = 0.0  # New variable for total difference
    total_weight_diff = 0.0  # New variable for total weight difference
    
    # First initialize all asset class groups from the holdings
    for holding in holdings:
        asset_class = holding.fund.benchmark.asset_class
        if asset_class not in holdings_by_asset_class:
            holdings_by_asset_class[asset_class] = []
            asset_class_sums[asset_class] = 0.0
            asset_class_strategic_sums[asset_class] = 0.0
            asset_class_diff_sums[asset_class] = 0.0
            asset_class_weight_diffs[asset_class] = 0.0
        holdings_by_asset_class[asset_class].append(holding)
    
    # Then calculate amounts and sums
    for holding in holdings:
        try:
            # Get the price based on use_myprice flag
            if not holding.use_myprice:
                price_to_use = holding.fund.price
            else:
                price_to_use = holding.price_per_unit

            # Calculate amount = price * units
            if price_to_use is not None:
                holding.calculated_amount = price_to_use * (holding.units or 0.0)
                total_portfolio_value += holding.calculated_amount
                
                # Track amount by asset class
                asset_class = holding.fund.benchmark.asset_class
                asset_class_sums[asset_class] += holding.calculated_amount
                asset_class_strategic_sums[asset_class] += holding.strategic_weight * 100
            else:
                holding.calculated_amount = None
        except (TypeError, ValueError):
            holding.calculated_amount = None
    
    # Calculate weight percentages and strategic amounts
    for holding in holdings:
        try:
            if holding.calculated_amount and total_portfolio_value > 0:
                holding.calculated_weight = (holding.calculated_amount / total_portfolio_value) * 100
                total_weight += holding.calculated_weight
                total_strategic_weight += holding.strategic_weight * 100
                
                # Calculate strategic amount using the final total portfolio value
                holding.strategic_amount = (holding.strategic_weight * total_portfolio_value)
                
                # Calculate difference between actual and strategic amount
                holding.diff_amount = holding.calculated_amount - holding.strategic_amount
                total_diff += holding.diff_amount
                
                # Calculate difference between actual and strategic weight
                holding.diff_weight = holding.calculated_weight - (holding.strategic_weight * 100)
                total_weight_diff += holding.diff_weight
                
                # Add to asset class sums
                asset_class = holding.fund.benchmark.asset_class
                asset_class_diff_sums[asset_class] += holding.diff_amount
                asset_class_weight_diffs[asset_class] += holding.diff_weight
            else:
                holding.calculated_weight = None
                holding.strategic_amount = None
                holding.diff_amount = None
                holding.diff_weight = None
        except (TypeError, ValueError, ZeroDivisionError):
            holding.calculated_weight = None
            holding.strategic_amount = None
            holding.diff_amount = None
            holding.diff_weight = None
    
    # Sort the grouped holdings according to ASSET_CLASSES order
    sorted_holdings_by_asset_class = {}
    for asset_class in ASSET_CLASSES:
        if asset_class in holdings_by_asset_class:
            sorted_holdings_by_asset_class[asset_class] = holdings_by_asset_class[asset_class]
    
    # Add any asset classes not in ASSET_CLASSES at the end
    for asset_class, holdings_list in holdings_by_asset_class.items():
        if asset_class not in sorted_holdings_by_asset_class:
            sorted_holdings_by_asset_class[asset_class] = holdings_list
    
    # Calculate max absolute difference for bar scaling
    max_positive_holding_diff = max(
        (h.diff_amount for h in holdings if h.diff_amount is not None and h.diff_amount > 0),
        default=0
    )
    
    max_negative_holding_diff = abs(min(
        (h.diff_amount for h in holdings if h.diff_amount is not None and h.diff_amount < 0),
        default=0
    ))
    
    max_asset_class_diff = max(
        (abs(d) for d in asset_class_diff_sums.values()),
        default=0
    )
    
    return render_template('view_portfolio.html', 
                         portfolio=portfolio, 
                         holdings=holdings,
                         holdings_by_asset_class=sorted_holdings_by_asset_class,
                         asset_class_sums=asset_class_sums,
                         asset_class_strategic_sums=asset_class_strategic_sums,
                         asset_class_diff_sums=asset_class_diff_sums,
                         asset_class_weight_diffs=asset_class_weight_diffs,
                         total_portfolio_value=total_portfolio_value,
                         total_weight=total_weight,
                         total_strategic_weight=total_strategic_weight,
                         total_diff=total_diff,
                         total_weight_diff=total_weight_diff,
                         max_positive_holding_diff=max_positive_holding_diff,
                         max_negative_holding_diff=max_negative_holding_diff,
                         max_asset_class_diff=max_asset_class_diff)


@app.route('/edit_portfolio/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_portfolio(id):
    portfolio = Portfolio.query.filter_by(id=id, user_id=current_user.id).first_or_404()
    
    if request.method == 'POST':
        portfolio_name = request.form.get('portfolio_name', '').strip()
        
        # Validate portfolio name
        if not portfolio_name:
            flash('Portfolio name is required', 'error')
            return render_template('edit_portfolio.html', portfolio=portfolio, error='Portfolio name is required')
            
        if len(portfolio_name) > 40:
            flash('Portfolio name must be 40 characters or less', 'error')
            return render_template('edit_portfolio.html', portfolio=portfolio, error='Portfolio name must be 40 characters or less')
        
        # Check if user already has another portfolio with this name
        existing_portfolio = Portfolio.query.filter_by(
            user_id=current_user.id,
            portfolio_name=portfolio_name
        ).filter(Portfolio.id != id).first()
        
        if existing_portfolio:
            flash('You already have a portfolio with this name', 'error')
            return render_template('edit_portfolio.html', portfolio=portfolio, error='You already have a portfolio with this name')
            
        try:
            portfolio.portfolio_name = portfolio_name
            db.session.commit()
            flash('Portfolio updated successfully!', 'success')
            return redirect(url_for('get_portfolios'))
        except Exception as e:
            db.session.rollback()
            flash('An error occurred while updating the portfolio. Please try again.', 'error')
            return render_template('edit_portfolio.html', portfolio=portfolio, error='An error occurred. Please try again.')
    
    return render_template('edit_portfolio.html', portfolio=portfolio)

@app.route('/delete_portfolio/<int:id>', methods=['POST'])
@login_required
def delete_portfolio(id):
    portfolio = Portfolio.query.filter_by(id=id, user_id=current_user.id).first_or_404()
   
       # Check if user is allowed to delete portfolio
    if not current_user.is_admin() and portfolio.user_id != current_user.id:
        flash('You do not have permission to delete this portfolio', 'error')
        return redirect(url_for('get_portfolios'))

    # Check if this is the default portfolio
    if portfolio.is_default:
        flash('Cannot delete the default portfolio', 'error')
        return redirect(url_for('get_portfolios'))
    
    # Check if portfolio has any holdings
    related_holdings = Holding.query.filter_by(portfolio_id=id).all()
    if related_holdings:
        fund_list = []
        for holding in related_holdings:
            fund_name = holding.fund.fund_name if holding.fund else 'Unknown Fund'
            fund_list.append(f"• {fund_name}")
        
        error_message = "This portfolio contains the following funds:\n"
        error_message += "\n".join(fund_list)
        error_message += "\n\nPlease remove all funds from this portfolio before deleting it."
        flash(error_message, 'error')
        return redirect(url_for('get_portfolios'))
    
    try:
        db.session.delete(portfolio)
        db.session.commit()
        flash('Portfolio was successfully deleted', 'success')
        return redirect(url_for('get_portfolios'))
    except Exception as e:
        db.session.rollback()
        flash(f'An error occurred while deleting the portfolio: {str(e)}', 'error')
        return redirect(url_for('get_portfolios'))


@app.route('/portfolio_strategy/<int:id>', methods=['GET', 'POST'])
@login_required
def portfolio_strategy(id):
    try:
        # Check if portfolio exists
        portfolio = Portfolio.query.filter_by(id=id).first()
        if not portfolio:
            flash('Portfolio not found', 'error')
            return redirect(url_for('get_portfolios'))
        # Check if user has permission to access this portfolio
        if portfolio.user_id != current_user.id:
            flash('You do not have permission to access this portfolio', 'error')
            return redirect(url_for('get_portfolios'))

        # Handle POST request for updating strategic weight or description
        if request.method == 'POST':
            action = request.form.get('action')
            if action == 'update_strategy_description':
                desc = request.form.get('strategy_description', '').strip()
                if len(desc) > 500:
                    flash('Description must be 500 characters or less.', 'danger')
                else:
                    portfolio.strategy_description = desc
                    db.session.commit()
                    flash('Strategy description updated.', 'success')
                return redirect(url_for('portfolio_strategy', id=id))
            # Existing code for updating strategic weight
            holding_id = request.form.get('holding_id')
            strategic_weight = request.form.get('strategic_weight')
            
            # Validate required fields
            if not holding_id or not strategic_weight:
                flash('Missing required fields', 'error')
                return redirect(url_for('portfolio_strategy', id=id))
            
            try:
                # Get and validate holding
                holding = Holding.query.filter_by(id=holding_id).first()
                if not holding:
                    flash('Holding not found', 'error')
                    return redirect(url_for('portfolio_strategy', id=id))
                
                # Verify holding belongs to user and portfolio
                if holding.user_id != current_user.id or holding.portfolio_id != portfolio.id:
                    flash('You do not have permission to modify this holding', 'error')
                    return redirect(url_for('portfolio_strategy', id=id))
                
                # Convert and validate strategic weight
                try:
                    strategic_weight = float(strategic_weight)
                except ValueError:
                    flash('Invalid strategic weight format', 'error')
                    return redirect(url_for('portfolio_strategy', id=id))
                
                if strategic_weight < 0 or strategic_weight > 100:
                    flash('Strategic weight must be between 0 and 100', 'error')
                    return redirect(url_for('portfolio_strategy', id=id))
                
                # Update holding
                holding.strategic_weight = strategic_weight / 100  # Convert percentage to decimal
                db.session.commit()
                flash('Strategic weight updated successfully', 'success')
                
            except Exception as e:
                db.session.rollback()
                flash('An error occurred while updating the strategic weight', 'error')
                return redirect(url_for('portfolio_strategy', id=id))
            
            return redirect(url_for('portfolio_strategy', id=id))
        
        # GET request - get holdings with their strategic weights
        holdings = Holding.query.filter_by(portfolio_id=id).join(Holding.fund).order_by(Fund.fund_name).all()
        
        # Check if portfolio has any holdings
        if not holdings:
            flash('This portfolio has no holdings. Add some funds to set strategic weights.', 'info')
            return render_template('portfolio_strategy.html', 
                                portfolio=portfolio,
                                holdings=[],
                                holdings_by_asset_class={},
                                asset_class_strategic_sums={},
                                total_strategic_weight=0.0,
                                chart_json=None)
        
        # Group holdings by asset class and calculate sums
        holdings_by_asset_class = {}
        asset_class_strategic_sums = {}
        total_strategic_weight = 0.0
        
        for holding in holdings:
            asset_class = holding.fund.benchmark.asset_class
            if asset_class not in holdings_by_asset_class:
                holdings_by_asset_class[asset_class] = []
                asset_class_strategic_sums[asset_class] = 0.0
            holdings_by_asset_class[asset_class].append(holding)
            asset_class_strategic_sums[asset_class] += holding.strategic_weight * 100
            total_strategic_weight += holding.strategic_weight * 100
        
        # Create pie chart data
        labels = []
        values = []
        for asset_class, weight in asset_class_strategic_sums.items():
            if weight > 0:
                labels.append(asset_class)
                values.append(float(weight))

        # Create Plotly figure
        if values:
            fig = go.Figure(data=[go.Pie(
                labels=labels,
                values=values,
                hole=0.4,
                textinfo='value+percent',
                textposition='inside',
                textfont=dict(size=14),
                marker=dict(colors=px.colors.qualitative.Set3[:len(labels)]),
                hovertemplate='<b>%{label}</b><br>%{value:.1f}%<extra></extra>'
            )])
            
            fig.update_traces(
                texttemplate='%{value:.1f}%'
            )
            
            fig.update_layout(
                showlegend=True,
                legend=dict(
                    orientation="v",
                    yanchor="middle",
                    y=0.5,
                    xanchor="left",
                    x=1.05,
                    font=dict(size=12),
                    bgcolor='rgba(255,255,255,0.8)',
                    bordercolor='rgba(0,0,0,0.1)',
                    borderwidth=1
                ),
                margin=dict(t=20, l=20, r=120, b=20),
                height=260,            # Increased height by ~1cm (40px)
                autosize=True,
                paper_bgcolor='rgba(0,0,0,0)',
                plot_bgcolor='rgba(0,0,0,0)',
                dragmode=False
            )
            
            chart_json = json.loads(fig.to_json())
        else:
            chart_json = None
        
        # Check if total strategic weight is not 100%
        if abs(total_strategic_weight - 100.0) > 0:  
            flash(f'Warning: Strategic weights sum to {total_strategic_weight:.1f}%, not 100%', 'warning')
        
        # Sort the grouped holdings according to ASSET_CLASSES order
        sorted_holdings_by_asset_class = {}
        for asset_class in ASSET_CLASSES:
            if asset_class in holdings_by_asset_class:
                sorted_holdings_by_asset_class[asset_class] = holdings_by_asset_class[asset_class]
        
        # Add any asset classes not in ASSET_CLASSES at the end
        for asset_class, holdings_list in holdings_by_asset_class.items():
            if asset_class not in sorted_holdings_by_asset_class:
                sorted_holdings_by_asset_class[asset_class] = holdings_list
        
        return render_template('portfolio_strategy.html', 
                             portfolio=portfolio,
                             holdings=holdings,
                             holdings_by_asset_class=sorted_holdings_by_asset_class,
                             asset_class_strategic_sums=asset_class_strategic_sums,
                             total_strategic_weight=total_strategic_weight,
                             chart_json=chart_json)
                             
    except Exception as e:
        # Log the error for debugging
        flash('An unexpected error occurred', 'error')
        return redirect(url_for('get_portfolios'))

@app.route('/portfolio_holdings/<int:id>', methods=['GET', 'POST'])
@login_required
def portfolio_holdings(id):
    try:
        from some_data import ASSET_CLASSES
        
        # Check if portfolio exists
        portfolio = Portfolio.query.filter_by(id=id).first()
        if not portfolio:
            flash('Portfolio not found', 'error')
            return redirect(url_for('get_portfolios'))
        
        # Check if user has permission to view this portfolio
        if portfolio.user_id != current_user.id:
            flash('You do not have permission to view this portfolio', 'error')
            return redirect(url_for('get_portfolios'))
            
        # Handle POST requests
        if request.method == 'POST':
            holding_id = request.form.get('holding_id')
            if not holding_id:
                flash('Invalid request', 'error')
                return redirect(url_for('portfolio_holdings', id=id))
                
            holding = Holding.query.filter_by(id=holding_id, user_id=current_user.id).first()
            if not holding:
                flash('Holding not found', 'error')
                return redirect(url_for('portfolio_holdings', id=id))
            
            # Handle different actions
            action = request.form.get('action')
            
            if action == 'update_units':
                try:
                    units = float(request.form.get('units', 0))
                    if units < 0:
                        raise ValueError("Units cannot be negative")
                    holding.units = units
                    db.session.commit()
                    flash('Units updated successfully', 'success')
                except ValueError as e:
                    flash(f'Invalid units value: {str(e)}', 'error')
                    return redirect(url_for('portfolio_holdings', id=id))
                    
            elif action == 'update_myprice':
                try:
                    myprice = float(request.form.get('myprice', 0))
                    if myprice < 0:
                        raise ValueError("Price cannot be negative")
                    holding.price_per_unit = myprice
                    db.session.commit()
                    flash('MyPrice updated successfully', 'success')
                except ValueError as e:
                    flash(f'Invalid price value: {str(e)}', 'error')
                    return redirect(url_for('portfolio_holdings', id=id))
                    
            elif action == 'toggle_myprice':
                holding.use_myprice = 1 if holding.use_myprice == 0 else 0
                db.session.commit()
                flash('Price source updated successfully', 'success')
                
            return redirect(url_for('portfolio_holdings', id=id))
        
        # Get holdings with their fund and benchmark data
        holdings = Holding.query.filter_by(portfolio_id=id).join(Holding.fund).order_by(Fund.fund_name).all()
        
        # Initialize dictionaries for tracking
        asset_class_sums = {}
        asset_class_strategic_sums = {}
        asset_class_diff_sums = {}
        asset_class_weight_diffs = {}
        holdings_by_asset_class = {}
        total_portfolio_value = 0.0
        total_weight = 0.0
        total_strategic_weight = 0.0
        total_diff = 0.0
        total_weight_diff = 0.0
        
        # First initialize all asset class groups from the holdings
        for holding in holdings:
            asset_class = holding.fund.benchmark.asset_class
            if asset_class not in holdings_by_asset_class:
                holdings_by_asset_class[asset_class] = []
                asset_class_sums[asset_class] = 0.0
                asset_class_strategic_sums[asset_class] = 0.0
                asset_class_diff_sums[asset_class] = 0.0
                asset_class_weight_diffs[asset_class] = 0.0
            holdings_by_asset_class[asset_class].append(holding)
        
        # Then calculate amounts and sums
        for holding in holdings:
            try:
                # Get the price based on use_myprice flag
                if not holding.use_myprice:
                    price_to_use = holding.fund.price
                else:
                    price_to_use = holding.price_per_unit

                # Calculate amount = price * units
                if price_to_use is not None:
                    holding.calculated_amount = price_to_use * (holding.units or 0.0)
                    total_portfolio_value += holding.calculated_amount
                    
                    # Track amount by asset class
                    asset_class = holding.fund.benchmark.asset_class
                    asset_class_sums[asset_class] += holding.calculated_amount
                    asset_class_strategic_sums[asset_class] += holding.strategic_weight * 100
                else:
                    holding.calculated_amount = None
            except (TypeError, ValueError):
                holding.calculated_amount = None
        
        # Calculate weight percentages and strategic amounts
        for holding in holdings:
            try:
                if holding.calculated_amount and total_portfolio_value > 0:
                    holding.calculated_weight = (holding.calculated_amount / total_portfolio_value) * 100
                    total_weight += holding.calculated_weight
                    total_strategic_weight += holding.strategic_weight * 100
                    
                    # Calculate strategic amount using the final total portfolio value
                    holding.strategic_amount = (holding.strategic_weight * total_portfolio_value)
                    
                    # Calculate difference between actual and strategic amount
                    holding.diff_amount = holding.calculated_amount - holding.strategic_amount
                    total_diff += holding.diff_amount
                    
                    # Calculate difference between actual and strategic weight
                    holding.diff_weight = holding.calculated_weight - (holding.strategic_weight * 100)
                    total_weight_diff += holding.diff_weight
                    
                    # Add to asset class sums
                    asset_class = holding.fund.benchmark.asset_class
                    asset_class_diff_sums[asset_class] += holding.diff_amount
                    asset_class_weight_diffs[asset_class] += holding.diff_weight
                else:
                    holding.calculated_weight = None
                    holding.strategic_amount = None
                    holding.diff_amount = None
                    holding.diff_weight = None
            except (TypeError, ValueError, ZeroDivisionError):
                holding.calculated_weight = None
                holding.strategic_amount = None
                holding.diff_amount = None
                holding.diff_weight = None
        
        # Sort the grouped holdings according to ASSET_CLASSES order
        sorted_holdings_by_asset_class = {}
        for asset_class in ASSET_CLASSES:
            if asset_class in holdings_by_asset_class:
                sorted_holdings_by_asset_class[asset_class] = holdings_by_asset_class[asset_class]
        
        # Add any asset classes not in ASSET_CLASSES at the end
        for asset_class, holdings_list in holdings_by_asset_class.items():
            if asset_class not in sorted_holdings_by_asset_class:
                sorted_holdings_by_asset_class[asset_class] = holdings_list
        
        return render_template('portfolio_holdings_view.html', 
                             portfolio=portfolio, 
                             holdings=holdings,
                             holdings_by_asset_class=sorted_holdings_by_asset_class,
                             asset_class_sums=asset_class_sums,
                             total_portfolio_value=total_portfolio_value,
                             total_weight=total_weight,
                             total_strategic_weight=total_strategic_weight)
                             
    except Exception as e:
        flash('An error occurred while loading the portfolio', 'error')
        return redirect(url_for('get_portfolios'))


# Holding routes
@app.route('/add_fund_to_portfolio/<int:fund_id>', methods=['POST'])
@login_required
def add_fund_to_portfolio(fund_id):
    try:
        # Validate portfolio_id from form
        portfolio_id = request.form.get('portfolio_id')
        if not portfolio_id:
            flash('Please select a portfolio', 'error')
            return redirect(url_for('get_funds'))
        
        try:
            portfolio_id = int(portfolio_id)
        except ValueError:
            flash('Invalid portfolio selection', 'error')
            return redirect(url_for('get_funds'))
        
        # Verify the portfolio belongs to the user and is not deleted
        portfolio = Portfolio.query.filter_by(
            id=portfolio_id,
            user_id=current_user.id
        ).first()
        
        if not portfolio:
            flash('Portfolio not found or you do not have permission to access it', 'error')
            return redirect(url_for('get_funds'))
        
        # Verify the fund exists and user has access
        fund = Fund.query.filter(
            (Fund.id == fund_id) & 
            ((Fund.user_id == current_user.id) | (Fund.generic_fund == 1))
        ).first()
        
        if not fund:
            flash('Fund not found or you do not have permission to access it', 'error')
            return redirect(url_for('get_funds'))
        
        # Check if holding already exists
        existing_holding = Holding.query.filter_by(
            fund_id=fund_id,
            portfolio_id=portfolio_id,
            user_id=current_user.id
        ).first()
        
        if existing_holding:
            flash(f'Fund {fund.fund_name} is already in portfolio {portfolio.portfolio_name}', 'warning')
            return redirect(url_for('get_funds'))
        
        # Create new holding with proper validation
        try:
            new_holding = Holding(
                fund_id=fund_id,
                portfolio_id=portfolio_id,
                user_id=current_user.id,
                units=0.0,  # Default to 0 units
                price_per_unit=fund.price if fund.price is not None else 0.0,  # Use fund's current price if available
                use_myprice=0,  # Default to using fund's price
                strategic_weight=0.0  # Default strategic weight
            )
            
            # Validate the holding before adding
            if not all([
                new_holding.fund_id,
                new_holding.portfolio_id,
                new_holding.user_id,
                new_holding.units is not None,
                new_holding.price_per_unit is not None,
                new_holding.use_myprice is not None,
                new_holding.strategic_weight is not None
            ]):
                raise ValueError("Invalid holding data")
            
            db.session.add(new_holding)
            db.session.commit()
            
            flash(f'Fund {fund.fund_name} added to portfolio {portfolio.portfolio_name} successfully', 'success')
            return redirect(url_for('portfolio_holdings', id=portfolio_id))
            
        except ValueError as ve:
            db.session.rollback()
            flash(f'Invalid holding data: {str(ve)}', 'error')
            return redirect(url_for('get_funds'))
            
    except Exception as e:
        db.session.rollback()

        flash('An error occurred while adding the fund to portfolio', 'error')
        return redirect(url_for('get_funds'))


@app.route('/holding/<int:id>', methods=['POST'])
@login_required
def delete_holding(id):
    try:
        # Get the holding and verify ownership
        holding = Holding.query.filter_by(id=id).first()
        if not holding:
            flash('Holding not found', 'error')
            return redirect(url_for('get_portfolios'))
            
        if holding.user_id != current_user.id:
            flash('You do not have permission to delete this holding', 'error')
            return redirect(url_for('get_portfolios'))
            
        # Get portfolio for redirect
        portfolio = holding.portfolio
        fund_name = holding.fund.fund_name if holding.fund else 'Unknown Fund'
        portfolio_id = portfolio.id if portfolio else None
        
        # Delete the holding
        db.session.delete(holding)
        db.session.commit()
        
        flash(f'Successfully deleted {fund_name} from portfolio', 'success')
        return redirect(url_for('portfolio_holdings', id=portfolio_id))
        
    except Exception as e:
        db.session.rollback()
        flash('An error occurred while deleting the holding', 'error')
        # If we have the portfolio ID, redirect there, otherwise go to portfolios list
        if 'portfolio' in locals() and portfolio:
            return redirect(url_for('portfolio_holdings', id=portfolio.id))
        return redirect(url_for('get_portfolios'))


@app.route('/debug/users')
def debug_users():
    users = User.query.all()
    user_list = []
    for user in users:
        user_list.append({
            'id': user.id,
            'username': user.username,
            'user_type': user.user_type
        })
    return jsonify(user_list)

@app.route('/edit_benchmark/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_benchmark(id):
    benchmark = Benchmark.query.get_or_404(id)
    
    # Check if user has permission to edit
    if benchmark.user_id != current_user.id:
        flash('You do not have permission to edit this benchmark', 'error')
        return redirect(url_for('get_benchmarks'))
    
    # Load risk factors and form options
    risk_factors = RiskFactor.query.all()
    form_options = {
        'asset_classes': ASSET_CLASSES,
        'regions': REGIONS,
        'market_types': MARKET_TYPES,
        'bond_ratings': BOND_RATING,
        'bond_types': BOND_TYPES,
        'vehicles': VEHICLE
    }
    
    if request.method == 'POST':
        # Get form data and strip whitespace
        benchmark_name = request.form.get('benchmark_name', '').strip()
        risk_factor_id = request.form.get('risk_factor_id', '').strip()
        asset_class = request.form.get('asset_class', '').strip()
        region = request.form.get('region', '').strip()
        developed = request.form.get('developed', '').strip()
        
        # Validate required fields
        required_fields = {
            'benchmark_name': benchmark_name,
            'risk_factor_id': risk_factor_id,
            'asset_class': asset_class,
            'region': region,
            'developed': developed
        }
        
        for field, value in required_fields.items():
            if not value:
                flash(f'{field.replace("_", " ").title()} is required', 'error')
                return render_template('edit_benchmark.html', 
                                    benchmark=benchmark,
                                    risk_factors=risk_factors,
                                    form_options=form_options)
        
        # Validate numeric fields
        numeric_fields = {
            'beta': request.form.get('beta'),
            'mod_duration': request.form.get('mod_duration'),
            'fx': request.form.get('fx'),
            'usd': request.form.get('usd'),
            'us': request.form.get('us')
        }
        
        numeric_values = {}
        for field, value in numeric_fields.items():
            if value:
                try:
                    numeric_values[field] = float(value)
                except ValueError:
                    flash(f'Invalid value for {field}. Please enter a valid number.', 'error')
                    return render_template('edit_benchmark.html', 
                                        benchmark=benchmark,
                                        risk_factors=risk_factors,
                                        form_options=form_options)
            else:
                numeric_values[field] = None
        
        try:
            # Update benchmark fields
            benchmark.benchmark_name = benchmark_name
            benchmark.risk_factor_id = risk_factor_id
            benchmark.asset_class = asset_class
            benchmark.region = region
            benchmark.developed = developed
            benchmark.bond_rating = request.form.get('bond_rating')
            benchmark.bond_type = request.form.get('bond_type')
            
            # Update numeric fields
            benchmark.beta = numeric_values['beta']
            benchmark.mod_duration = numeric_values['mod_duration']
            benchmark.fx = numeric_values['fx']
            benchmark.usd = numeric_values['usd']
            benchmark.us = numeric_values['us']
            
            db.session.commit()
            flash('Benchmark updated successfully!', 'success')
            return redirect(url_for('view_benchmark', id=benchmark.id))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating benchmark: {str(e)}', 'error')
            return render_template('edit_benchmark.html', 
                                benchmark=benchmark,
                                risk_factors=risk_factors,
                                form_options=form_options)
    
    return render_template('edit_benchmark.html', 
                         benchmark=benchmark,
                         risk_factors=risk_factors,
                         form_options=form_options)

@app.route('/edit_fund/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_fund(id):
    fund = Fund.query.get_or_404(id)
    
    # Check if user has permission to edit this fund
    if not current_user.is_admin() and (fund.generic_fund or fund.user_id != current_user.id):
        flash('You do not have permission to edit this fund.', 'danger')
        return redirect(url_for('get_funds'))
    
    # Prepare form options
    form_options = {
        'vehicles': VEHICLE
    }
    
    if request.method == 'POST':
        form_type = request.form.get('form_type')
        
        if form_type == 'price_date':
            # Handle price and date update
            price = request.form.get('price', '').strip()
            date = request.form.get('date', '').strip()
            
            # Validate required fields
            if not price or not date:
                flash('Both price and date are required.', 'danger')
                return redirect(url_for('edit_fund', id=id))
            
            try:
                price = float(price)
                date = datetime.strptime(date, '%Y-%m-%d').date()
            except ValueError:
                flash('Invalid price or date format.', 'danger')
                return redirect(url_for('edit_fund', id=id))
            
            # Update price and date
            fund.price = price
            fund.date = date
            db.session.commit()
            flash('Price and date updated successfully.', 'success')
            return redirect(url_for('edit_fund', id=id))
        else:
            # Handle regular fund update
            # Get and strip all form fields
            fund_name = request.form.get('fund_name', '').strip()
            long_name = request.form.get('long_name', '').strip()
            one_word_name = request.form.get('one_word_name', '').strip()
            ticker = request.form.get('ticker', '').strip()
            identifier = request.form.get('identifier', '').strip()
            vehicle = request.form.get('vehicle', '').strip()
            benchmark_id = request.form.get('benchmark_id', '').strip()
            
            # Validate required fields
            required_fields = {
                'fund_name': fund_name,
                'long_name': long_name,
                'one_word_name': one_word_name,
                'ticker': ticker,
                'identifier': identifier,
                'vehicle': vehicle,
                'benchmark_id': benchmark_id
            }
            
            for field, value in required_fields.items():
                if not value:
                    flash(f'{field.replace("_", " ").title()} is required.', 'danger')
                    return redirect(url_for('edit_fund', id=id))
            
            try:
                # Update fund fields
                fund.fund_name = fund_name
                fund.long_name = long_name
                fund.one_word_name = one_word_name
                fund.ticker = ticker
                fund.identifier = identifier
                fund.vehicle = vehicle
                fund.benchmark_id = benchmark_id
                
                db.session.commit()
                flash('Fund updated successfully.', 'success')
                return redirect(url_for('get_funds'))
            except Exception as e:
                db.session.rollback()
                flash(f'Error updating fund: {str(e)}', 'danger')
                return redirect(url_for('edit_fund', id=id))
    
    # Get benchmarks for the dropdown
    if current_user.is_admin():
        benchmarks = Benchmark.query.all()
    else:
        benchmarks = Benchmark.query.filter(
            (Benchmark.generic_benchmark == True) |
            (Benchmark.user_id == current_user.id)
        ).all()
    
    return render_template('edit_fund.html', fund=fund, benchmarks=benchmarks, form_options=form_options)

@app.route('/view_benchmark/<int:id>')
@login_required
def view_benchmark(id):
    benchmark = Benchmark.query.get_or_404(id)
    
    # Check if user has permission to view
    if not current_user.is_admin() and benchmark.user_id != current_user.id and not benchmark.generic_benchmark:
        flash('You do not have permission to view this benchmark', 'error')
        return redirect(url_for('get_benchmarks'))
    
    return render_template('view_benchmark.html', benchmark=benchmark)

@app.route('/privacy_policy')
def privacy_policy():
    return render_template('privacy_policy.html', now=datetime.utcnow())

@app.route('/accept_cookies', methods=['POST'])
def accept_cookies():
    response = jsonify({'status': 'success'})
    # Set a permanent cookie that expires in 1 year
    response.set_cookie('cookie_consent', 'accepted', max_age=31536000, httponly=False, samesite='Lax')
    return response

@app.route('/decline_cookies', methods=['POST'])
def decline_cookies():
    response = jsonify({'status': 'success'})
    # Set a permanent cookie that expires in 1 year to remember the decline
    response.set_cookie('cookie_consent', 'declined', max_age=31536000, httponly=False, samesite='Lax')
    return response

@app.route('/reset_cookie_consent')
def reset_cookie_consent():
    response = redirect(url_for('home'))
    response.delete_cookie('cookie_consent')
    return response

@app.route('/kill')
def kill_app():
    func = request.environ.get('werkzeug.server.shutdown')
    if func is None:
        raise RuntimeError('Not running with the Werkzeug Server')
    func()
    return 'Server shutting down...'

@app.route('/delete_profile', methods=['POST'])
@login_required
def delete_profile():
    try:
        # Start a transaction
        db.session.begin_nested()
        
        # 1. Delete all holdings
        Holding.query.filter_by(user_id=current_user.id).delete()
        
        # 2. Delete all portfolios
        Portfolio.query.filter_by(user_id=current_user.id).delete()
        
        # 3. Delete all funds
        Fund.query.filter_by(user_id=current_user.id).delete()
        
        # 4. Delete all benchmarks
        Benchmark.query.filter_by(user_id=current_user.id).delete()
        
        # 5. Delete the user
        db.session.delete(current_user)
        
        # Commit the transaction
        db.session.commit()
        
        # Log out the user
        logout_user()
        
        # Clear session
        session.clear()
        
        flash('Your profile and all associated data have been deleted successfully.', 'success')
        return redirect(url_for('register'))
        
    except Exception as e:
        # Rollback in case of error
        db.session.rollback()
        flash('An error occurred while deleting your profile. Please try again.', 'error')
        return redirect(url_for('edit_profile'))

# Add LoginAttempt model for tracking failed login attempts
class LoginAttempt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), nullable=False)
    ip_address = db.Column(db.String(45), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def __repr__(self):
        return f'<LoginAttempt {self.email} at {self.timestamp}>'

# Add password reset routes
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        if not email:
            flash('Email is required', 'error')
            return render_template('forgot_password.html')
            
        user = User.query.filter_by(email=email).first()
        if user:
            # In a real application, you would:
            # 1. Generate a secure token
            # 2. Store it in the database with an expiration time
            # 3. Send a password reset email
            flash('If an account exists with this email, you will receive password reset instructions.', 'info')
        else:
            # Don't reveal whether the email exists or not
            flash('If an account exists with this email, you will receive password reset instructions.', 'error')
            
        return redirect(url_for('login'))
        
    return render_template('forgot_password.html')

# Add context processor for current year
@app.context_processor
def inject_now():
    return {'now': datetime.utcnow()}

@app.route('/view_fund/<int:id>')
@login_required
def view_fund(id):
    fund = Fund.query.get_or_404(id)
    
    # Check if user has permission to view
    if not current_user.is_admin() and fund.user_id != current_user.id and not fund.generic_fund:
        flash('You do not have permission to view this fund', 'error')
        return redirect(url_for('get_funds'))
    
    return render_template('view_fund.html', fund=fund)

if __name__ == '__main__':
    with app.app_context():
        # Create all tables
        db.create_all()
        # Allow port to be set via environment variable or command-line argument
        port = 5004
        if len(sys.argv) > 1:
            try:
                port = int(sys.argv[1])
            except ValueError:
                pass
        elif os.environ.get('PORT'):
            try:
                port = int(os.environ.get('PORT'))
            except ValueError:
                pass
        app.run(debug=True, host='0.0.0.0', port=port)
