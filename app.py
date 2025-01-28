from flask import Flask, request, jsonify, render_template, flash, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os
from datetime import datetime
import json

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///trading_bridge.db'
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Veritabanı modelleri
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    api_keys = db.relationship('ApiKey', backref='user', lazy=True)

class ApiKey(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    broker_name = db.Column(db.String(80), nullable=False)
    api_key = db.Column(db.String(200), nullable=False)
    api_secret = db.Column(db.String(200), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class TradingSignal(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    signal_data = db.Column(db.JSON, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    processed = db.Column(db.Boolean, default=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Webhook endpoint'i
@app.route('/webhook/<string:user_id>', methods=['POST'])
def webhook(user_id):
    try:
        data = request.json
        user = User.query.get(int(user_id))
        if not user:
            return jsonify({'error': 'User not found'}), 404

        # TradingView'den gelen sinyali kaydet
        signal = TradingSignal(
            user_id=user.id,
            signal_data=data
        )
        db.session.add(signal)
        db.session.commit()

        # Burada aracı kurum API'sine emir gönderme işlemi yapılacak
        process_trading_signal(signal)

        return jsonify({'status': 'success'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def process_trading_signal(signal):
    # Bu fonksiyon TradingView'den gelen sinyali işleyip aracı kuruma iletecek
    user = User.query.get(signal.user_id)
    api_keys = user.api_keys

    if not api_keys:
        return

    # Her bir API anahtarı için işlem yap
    for api_key in api_keys:
        try:
            # Burada aracı kurum API'sine bağlanma ve emir gönderme işlemleri yapılacak
            # Bu kısım aracı kurumun API yapısına göre özelleştirilmeli
            pass
        except Exception as e:
            print(f"Error processing signal for user {user.id}: {str(e)}")

# Login sayfası
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            flash('Başarıyla giriş yaptınız!', 'success')
            return redirect(url_for('dashboard'))
        
        flash('Kullanıcı adı veya şifre hatalı!', 'danger')
    return render_template('login.html')

# Register sayfası
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if User.query.filter_by(username=username).first():
            flash('Bu kullanıcı adı zaten kullanılıyor!', 'danger')
            return redirect(url_for('register'))
        
        user = User(
            username=username,
            password_hash=generate_password_hash(password)
        )
        db.session.add(user)
        db.session.commit()
        
        flash('Kayıt başarılı! Şimdi giriş yapabilirsiniz.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

# Logout route'u
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Başarıyla çıkış yaptınız.', 'success')
    return redirect(url_for('index'))

# Ana sayfa
@app.route('/')
def index():
    return render_template('index.html')

# Dashboard
@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

# API Anahtarı ekleme
@app.route('/add_api_key', methods=['GET', 'POST'])
@login_required
def add_api_key():
    if request.method == 'POST':
        broker_name = request.form.get('broker_name')
        api_key = request.form.get('api_key')
        api_secret = request.form.get('api_secret')

        new_api_key = ApiKey(
            broker_name=broker_name,
            api_key=api_key,
            api_secret=api_secret,
            user_id=current_user.id
        )
        db.session.add(new_api_key)
        db.session.commit()

        flash('API anahtarı başarıyla eklendi!', 'success')
        return redirect(url_for('dashboard'))

    return render_template('add_api_key.html')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    port = int(os.environ.get('PORT', 5001))
    app.run(debug=False, host='0.0.0.0', port=port)
