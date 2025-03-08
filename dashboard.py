#!/usr/bin/env python3
import sqlite3
from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO
import argparse
import time

app = Flask(__name__)
socketio = SocketIO(app)
DATABASE = None

def init_db():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS findings
                 (id INTEGER PRIMARY KEY, 
                  type TEXT, 
                  target TEXT, 
                  payload TEXT, 
                  timestamp DATETIME,
                  ip TEXT,
                  user_agent TEXT,
                  location TEXT)''')
    conn.commit()
    conn.close()

@app.route('/')
def dashboard():
    return render_template('dashboard.html')

@app.route('/data')
def get_data():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute("SELECT * FROM findings ORDER BY timestamp DESC LIMIT 100")
    data = [dict(zip([col[0] for col in c.description], row)) for row in c.fetchall()]
    conn.close()
    return jsonify(data)

@app.route('/blind', methods=['POST'])
def blind_callback():
    entry = {
        'type': 'Blind XSS',
        'target': request.remote_addr,
        'payload': request.args.get('payload', ''),
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
        'ip': request.headers.get('X-Real-IP', request.remote_addr),
        'user_agent': request.headers.get('User-Agent'),
        'location': f"{request.headers.get('X-GeoIP-Country', 'Unknown')}"
    }
    
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('''INSERT INTO findings 
                 (type, target, payload, timestamp, ip, user_agent, location)
                 VALUES (?,?,?,?,?,?,?)''',
              (entry['type'], entry['target'], entry['payload'],
               entry['timestamp'], entry['ip'], 
               entry['user_agent'], entry['location']))
    conn.commit()
    conn.close()
    
    socketio.emit('new_entry', entry)
    return 'OK'

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, default=1337)
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--db', required=True)
    args = parser.parse_args()
    
    DATABASE = args.db
    init_db()
    
    socketio.run(app, host=args.host, port=args.port)
