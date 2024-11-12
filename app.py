from flask import Flask, render_template, redirect, url_for, request, jsonify, flash
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask_socketio import SocketIO
from config import Config
from models import db, User, Alert
from ids.sniffing import start_sniffing
from datetime import datetime, timedelta
import threading

app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)
socketio = SocketIO(app, async_mode='threading')
login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes and views
@app.route('/')
@login_required
def index():
    alerts = Alert.query.order_by(Alert.timestamp.desc()).limit(100).all()
    return render_template('dashboard.html', alerts=alerts)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user is None or not user.check_password(password):
            flash('Invalid username or password')
            return redirect(url_for('login'))
        login_user(user)
        return redirect(url_for('index'))
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/chart-data')
@login_required
def chart_data():
    # Fetch data for the last hour
    one_hour_ago = datetime.utcnow() - timedelta(hours=1)
    alerts = Alert.query.filter(Alert.timestamp >= one_hour_ago).all()
    timestamps = [alert.timestamp.isoformat() for alert in alerts]
    alert_counts = {}
    for alert in alerts:
        key = alert.timestamp.strftime('%Y-%m-%d %H:%M')
        alert_counts[key] = alert_counts.get(key, 0) + 1
    data = {
        'timestamps': list(alert_counts.keys()),
        'values': list(alert_counts.values())
    }
    return jsonify(data)

# Start packet sniffing in a separate thread
def start_ids():
    threading.Thread(target=start_sniffing).start()

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        # Create an admin user if not exists
        if User.query.filter_by(username='admin').first() is None:
            admin = User(username='admin')
            admin.set_password('admin123')
            db.session.add(admin)
            db.session.commit()
    start_ids()
    socketio.run(app, host='0.0.0.0', port=5000)
