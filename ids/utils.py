from flask_socketio import SocketIO
from models import db, Alert
from datetime import datetime
from app import socketio

def notify_ui(message):
    socketio.emit('new_alert', {'message': message})

def save_alert(alert_type, source_ip, details):
    alert = Alert(
        timestamp=datetime.utcnow(),
        alert_type=alert_type,
        source_ip=source_ip,
        details=details
    )
    db.session.add(alert)
    db.session.commit()
