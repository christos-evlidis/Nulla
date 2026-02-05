# Gevent must be patched first so one worker can handle WebSockets + HTTP concurrently
from gevent import monkey
monkey.patch_all()

from flask import Flask, request, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_sock import Sock
import os
from datetime import datetime, timedelta, timezone
import time
import secrets
import json
import base64
import uuid
import threading
import sys
from collections import deque
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
import jwt

# Optional Redis for cross-instance presence (e.g. Render with multiple instances).
# Client is created lazily per worker so each gunicorn worker has its own connection
# (shared connection after fork is broken).
_redis_url = os.environ.get('REDIS_URL') or ''
_redis_client = None
_redis_enabled = bool(_redis_url)


def _get_redis_client():
    """Return Redis client, creating one per process (per gunicorn worker)."""
    global _redis_client
    if not _redis_url:
        return None
    if _redis_client is None:
        try:
            import redis
            _redis_client = redis.from_url(_redis_url)
            _redis_client.ping()
        except Exception as e:
            _log_app(f'redis connect failed: {e}')
            return None
    return _redis_client


REDIS_ONLINE_KEY = 'nulla:online_users'
REDIS_WS_CHAN_PREFIX = 'nulla:ws:user:'

# In-app log buffer (last N lines), also printed to stderr
_app_log_buffer = deque(maxlen=500)


def _log_app(msg):
    """Append a line to the in-app log buffer and to stderr."""
    ts = datetime.now(timezone.utc).strftime('%H:%M:%S')
    line = f'[{ts}] {msg}'
    _app_log_buffer.append(line)
    print(line, file=sys.stderr, flush=True)


app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*", "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"], "allow_headers": ["Content-Type", "Authorization"]}})
sock = Sock(app)


app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_urlsafe(32))

data_dir = os.environ.get('DATA_DIR', os.path.join(os.path.dirname(__file__), 'dbs'))
os.makedirs(data_dir, exist_ok=True)
db_path = os.path.join(data_dir, 'main.db')

db_path = db_path.replace('\\', '/')
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


db = SQLAlchemy(app)


class User(db.Model):
    
    __tablename__ = 'users'
    
    userId = db.Column(db.String(255), primary_key=True)
    signPublicKeyJwk = db.Column(db.Text, nullable=False)
    dhPublicKeyJwk = db.Column(db.Text, nullable=False)
    createdAt = db.Column(db.DateTime, nullable=False)


class ContactRequest(db.Model):
    
    __tablename__ = 'contact_requests'
    
    requestId = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    fromUserId = db.Column(db.String(255), db.ForeignKey('users.userId', ondelete='CASCADE'), nullable=False)
    toUserId = db.Column(db.String(255), db.ForeignKey('users.userId', ondelete='CASCADE'), nullable=False)
    status = db.Column(db.String(20), nullable=False, default='pending')
    createdAt = db.Column(db.DateTime, nullable=False)
    respondedAt = db.Column(db.DateTime, nullable=True)


class Chat(db.Model):
    
    __tablename__ = 'chats'
    
    chatId = db.Column(db.String(512), primary_key=True)
    userA = db.Column(db.String(255), db.ForeignKey('users.userId', ondelete='CASCADE'), nullable=False)
    userB = db.Column(db.String(255), db.ForeignKey('users.userId', ondelete='CASCADE'), nullable=False)
    createdAt = db.Column(db.DateTime, nullable=False)


class Message(db.Model):
    
    __tablename__ = 'messages'
    
    msgId = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    chatId = db.Column(db.String(512), db.ForeignKey('chats.chatId', ondelete='CASCADE'), nullable=False, index=True)
    sessionId = db.Column(db.String(255), nullable=False, index=True)
    senderId = db.Column(db.String(255), db.ForeignKey('users.userId', ondelete='CASCADE'), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc), index=True)
    ciphertext = db.Column(db.Text, nullable=False)
    iv = db.Column(db.String(64), nullable=False)
    ciphertext_len = db.Column(db.Integer, nullable=True)
    isFile = db.Column(db.Boolean, nullable=False, default=False)
    encryptedMetadata = db.Column(db.Text, nullable=True)
    encryptedMetadataIv = db.Column(db.String(64), nullable=True)


class Nonce(db.Model):
    
    __tablename__ = 'nonces'
    
    nonce = db.Column(db.String(255), primary_key=True)
    userId = db.Column(db.String(255), db.ForeignKey('users.userId', ondelete='CASCADE'), nullable=False, index=True)
    expiresAt = db.Column(db.BigInteger, nullable=False, index=True)
    createdAt = db.Column(db.BigInteger, nullable=False, default=lambda: int(time.time() * 1000))


JWT_SECRET = app.config['SECRET_KEY']
JWT_ALGORITHM = 'HS256'
TOKEN_EXPIRY = timedelta(hours=24)


def verify_jwt_token(token):
    
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def require_auth(f):
    
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Missing or invalid authorization header'}), 401
        
        token = auth_header.split(' ')[1]
        payload = verify_jwt_token(token)
        if not payload:
            return jsonify({'error': 'Invalid or expired token'}), 401
        
        request.user_id = payload.get('userId')
        return f(*args, **kwargs)
    wrapper.__name__ = f.__name__
    return wrapper


def verify_signature(publicKeyJwk, data, signature_b64):
    
    try:


        padding = len(signature_b64) % 4
        if padding:
            signature_b64 += '=' * (4 - padding)
        
        signature_bytes = base64.urlsafe_b64decode(signature_b64)
        


        if len(signature_bytes) == 64:

            r = int.from_bytes(signature_bytes[:32], 'big')
            s = int.from_bytes(signature_bytes[32:], 'big')
            

            from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
            signature_der = encode_dss_signature(r, s)
        else:

            signature_der = signature_bytes
        

        x_bytes = base64.urlsafe_b64decode(publicKeyJwk['x'] + '==')
        y_bytes = base64.urlsafe_b64decode(publicKeyJwk['y'] + '==')
        

        public_key = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(),
            bytes([0x04]) + x_bytes + y_bytes
        )
        

        public_key.verify(
            signature_der,
            data.encode('utf-8'),
            ec.ECDSA(hashes.SHA256())
        )
        
        return True
    except Exception as e:
        return False


@app.route('/api/register', methods=['POST', 'OPTIONS'])
def register():
    
    if request.method == 'OPTIONS':
        return '', 200
    
    try:
        data = request.get_json()
        
        if not data or 'userId' not in data:
            return jsonify({'error': 'Missing userId'}), 400
        
        if 'signPublicKeyJwk' not in data or 'dhPublicKeyJwk' not in data:
            return jsonify({'error': 'Missing public keys'}), 400
        
        userId = data['userId']
        signPublicKeyJwk = data['signPublicKeyJwk']
        dhPublicKeyJwk = data['dhPublicKeyJwk']
        

        existing_user = User.query.filter_by(userId=userId).first()
        if existing_user:

            existing_user.signPublicKeyJwk = json.dumps(signPublicKeyJwk)
            existing_user.dhPublicKeyJwk = json.dumps(dhPublicKeyJwk)
            db.session.commit()
            return jsonify({'ok': True, 'message': 'Account updated'})
        

        user = User(
            userId=userId,
            signPublicKeyJwk=json.dumps(signPublicKeyJwk),
            dhPublicKeyJwk=json.dumps(dhPublicKeyJwk),
            createdAt=datetime.now(timezone.utc)
        )
        
        db.session.add(user)
        db.session.flush()
        db.session.commit()
        

        saved_user = User.query.filter_by(userId=userId).first()
        if not saved_user:
            return jsonify({'error': 'User was not saved to database'}), 500
        
        return jsonify({'ok': True, 'message': 'Account created'})
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@app.route('/api/auth/challenge', methods=['POST', 'OPTIONS'])
def auth_challenge():
    
    if request.method == 'OPTIONS':
        return '', 200
    
    try:
        data = request.get_json()
        userId = data.get('userId')
        
        if not userId:
            return jsonify({'error': 'Missing userId'}), 400
        

        user = User.query.filter_by(userId=userId).first()
        if not user:
            return jsonify({'error': 'User not found'}), 404
        

        cleanup_old_nonces()
        

        nonce = secrets.token_urlsafe(32)
        created_at_ms = int(time.time() * 1000)
        expires_at_ms = created_at_ms + (30 * 60 * 1000)
        
        nonce_record = Nonce(
            nonce=nonce,
            userId=userId,
            expiresAt=expires_at_ms,
            createdAt=created_at_ms
        )
        db.session.add(nonce_record)
        db.session.commit()
        
        return jsonify({'nonce': nonce})
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@app.route('/api/auth/verify', methods=['POST', 'OPTIONS'])
def auth_verify():
    
    if request.method == 'OPTIONS':
        return '', 200
    
    try:
        data = request.get_json()
        userId = data.get('userId')
        nonce = data.get('nonce')
        signature = data.get('signature')
        
        if not all([userId, nonce, signature]):
            return jsonify({'error': 'Missing required fields'}), 400
        

        nonce_record = Nonce.query.filter_by(nonce=nonce).first()
        if not nonce_record:
            return jsonify({'error': 'Invalid or expired challenge'}), 400
        
        if nonce_record.userId != userId:
            return jsonify({'error': 'Challenge userId mismatch'}), 400
        
        now_ms = int(time.time() * 1000)
        
        if nonce_record.expiresAt < now_ms:
            db.session.delete(nonce_record)
            db.session.commit()
            return jsonify({'error': 'Challenge expired'}), 400
        

        user = User.query.filter_by(userId=userId).first()
        if not user:
            return jsonify({'error': 'User not found'}), 404
        

        signPublicKeyJwk = json.loads(user.signPublicKeyJwk)
        is_valid = verify_signature(signPublicKeyJwk, nonce, signature)
        
        if not is_valid:
            return jsonify({'error': 'Invalid signature'}), 401
        

        db.session.delete(nonce_record)
        db.session.commit()
        

        token = jwt.encode(
            {
                'userId': userId,
                'exp': datetime.now(timezone.utc) + TOKEN_EXPIRY
            },
            JWT_SECRET,
            algorithm=JWT_ALGORITHM
        )
        
        return jsonify({'token': token})
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


def create_chat_and_delete_requests(userA, userB, request1, request2=None):
    

    sorted_users = sorted([userA, userB])
    chatId = f"{sorted_users[0]}_{sorted_users[1]}"
    

    request1_id = request1.requestId if request1 else None
    request2_id = request2.requestId if request2 else None
    

    existing_chat = Chat.query.filter_by(chatId=chatId).first()
    if not existing_chat:
        chat = Chat(
            chatId=chatId,
            userA=sorted_users[0],
            userB=sorted_users[1],
            createdAt=datetime.now(timezone.utc)
        )
        db.session.add(chat)
    

    if request1:
        db.session.delete(request1)
    if request2:
        db.session.delete(request2)
    
    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        return None
    
    return chatId

def get_chat_id_from_users(userA, userB):
    
    sorted_users = sorted([userA, userB])
    return f"{sorted_users[0]}_{sorted_users[1]}"


@app.route('/api/contacts/request', methods=['POST'])
@require_auth
def send_contact_request():
    
    try:
        data = request.get_json()
        toUserId = data.get('toUserId')
        
        if not toUserId:
            return jsonify({'error': 'Missing toUserId'}), 400
        
        fromUserId = request.user_id
        

        if fromUserId == toUserId:
            return jsonify({'error': 'Cannot send request to yourself'}), 400
        

        to_user = User.query.filter_by(userId=toUserId).first()
        if not to_user:
            return jsonify({'error': 'User not found'}), 404
        

        existing = ContactRequest.query.filter(
            ContactRequest.fromUserId == fromUserId,
            ContactRequest.toUserId == toUserId,
            ContactRequest.status.in_(['pending', 'accepted'])
        ).first()
        
        if existing:
            return jsonify({'error': 'Request already exists'}), 400
        

        userA, userB = sorted([fromUserId, toUserId])
        chatId = f"{userA}_{userB}"
        existing_chat = Chat.query.filter_by(chatId=chatId).first()
        
        if existing_chat:
            return jsonify({'error': 'Chat already exists with this user'}), 400
        

        reverse_request = ContactRequest.query.filter(
            ContactRequest.fromUserId == toUserId,
            ContactRequest.toUserId == fromUserId,
            ContactRequest.status == 'pending'
        ).first()
        
        if reverse_request:

            chatId = create_chat_and_delete_requests(fromUserId, toUserId, reverse_request)
            
            return jsonify({
                'ok': True,
                'chatId': chatId,
                'message': 'Mutual request detected - chat created automatically'
            })
        

        contact_request = ContactRequest(
            fromUserId=fromUserId,
            toUserId=toUserId,
            status='pending',
            createdAt=datetime.now(timezone.utc)
        )
        
        db.session.add(contact_request)
        db.session.commit()
        
        return jsonify({
            'ok': True,
            'requestId': contact_request.requestId,
            'message': 'Contact request sent'
        })
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@app.route('/api/contacts/requests/incoming', methods=['GET'])
@require_auth
def get_incoming_requests():
    
    try:
        userId = request.user_id
        
        requests = ContactRequest.query.filter_by(
            toUserId=userId,
            status='pending'
        ).order_by(ContactRequest.createdAt.desc()).all()
        
        result = []
        for req in requests:
            result.append({
                'id': req.requestId,
                'fromUserId': req.fromUserId,
                'toUserId': req.toUserId,
                'status': req.status,
                'timestamp': req.createdAt.isoformat()
            })
        
        return jsonify(result)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/contacts/requests/outgoing', methods=['GET'])
@require_auth
def get_outgoing_requests():
    
    try:
        userId = request.user_id
        
        requests = ContactRequest.query.filter_by(
            fromUserId=userId,
            status='pending'
        ).order_by(ContactRequest.createdAt.desc()).all()
        
        result = []
        for req in requests:
            result.append({
                'id': req.requestId,
                'fromUserId': req.fromUserId,
                'toUserId': req.toUserId,
                'status': req.status,
                'timestamp': req.createdAt.isoformat()
            })
        
        return jsonify(result)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/contacts/requests/<requestId>/accept', methods=['POST'])
@require_auth
def accept_contact_request(requestId):
    
    try:
        userId = request.user_id
        

        contact_request = ContactRequest.query.filter_by(
            requestId=requestId,
            toUserId=userId,
            status='pending'
        ).first()
        
        if not contact_request:
            return jsonify({'error': 'Request not found'}), 404
        

        reverse_request = ContactRequest.query.filter(
            ContactRequest.fromUserId == userId,
            ContactRequest.toUserId == contact_request.fromUserId,
            ContactRequest.status == 'pending'
        ).first()
        

        fromUserId = contact_request.fromUserId
        if not _is_user_online(fromUserId):
            debug = _online_check_debug(fromUserId)
            _log_app(
                'accept: requester not seen as online | '
                f'fromUserId={fromUserId[:12]}... | '
                f'in_this_process={debug["in_local"]} | '
                f'in_redis={debug["in_redis"]} | '
                f'redis_enabled={debug["redis_enabled"]} | '
                f'connections_in_this_process={debug["local_connection_count"]}'
            )
            return jsonify({'error': 'Other user is not online. Key exchange requires both users to be connected.'}), 400
        

        chatId = get_chat_id_from_users(fromUserId, userId)
        
        if reverse_request:

            _send_to_user(fromUserId, {
                'type': 'contact_request_accepted',
                'chatId': chatId,
                'initiator': userId,
                'requestId': requestId,
                'reverseRequestId': reverse_request.requestId,
                'message': 'Mutual request detected - initiate key exchange'
            })
            
            return jsonify({
                'ok': True,
                'chatId': chatId,
                'initiator': True,
                'requestId': requestId,
                'reverseRequestId': reverse_request.requestId,
                'message': 'Mutual request detected - initiate key exchange'
            })
        

        _send_to_user(fromUserId, {
            'type': 'contact_request_accepted',
            'chatId': chatId,
            'initiator': userId,
            'requestId': requestId
        })
        
        return jsonify({
            'ok': True,
            'chatId': chatId,
            'initiator': True,
            'requestId': requestId,
            'message': 'Contact request accepted. Initiate key exchange.'
        })
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@app.route('/api/contacts/requests/<requestId>/reject', methods=['POST'])
@require_auth
def reject_contact_request(requestId):
    
    try:
        userId = request.user_id
        
        contact_request = ContactRequest.query.filter_by(
            requestId=requestId,
            toUserId=userId,
            status='pending'
        ).first()
        
        if not contact_request:
            return jsonify({'error': 'Request not found'}), 404
        

        db.session.delete(contact_request)
        db.session.commit()
        
        return jsonify({'ok': True, 'message': 'Contact request rejected and deleted'})
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@app.route('/api/chats', methods=['GET'])
@require_auth
def get_chats():
    
    try:
        userId = request.user_id
        

        chats = Chat.query.filter(
            (Chat.userA == userId) | (Chat.userB == userId)
        ).order_by(Chat.createdAt.desc()).all()
        
        result = []
        for chat in chats:

            other_user = chat.userB if chat.userA == userId else chat.userA
            
            result.append({
                'chatId': chat.chatId,
                'otherUserId': other_user,
                'createdAt': chat.createdAt.isoformat()
            })
        
        return jsonify(result)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


def _is_user_online(user_id):
    """True if user has an active WebSocket (this process or, with Redis, any process)."""
    if user_id in active_connections:
        return True
    r = _get_redis_client()
    if r:
        try:
            return r.sismember(REDIS_ONLINE_KEY, user_id)
        except Exception:
            pass
    return False


def _online_check_debug(user_id):
    """Return a dict explaining why user is (not) seen as online, for logging."""
    in_local = user_id in active_connections
    in_redis = False
    r = _get_redis_client()
    if r:
        try:
            in_redis = r.sismember(REDIS_ONLINE_KEY, user_id)
        except Exception:
            pass
    return {
        'in_local': in_local,
        'in_redis': in_redis,
        'redis_enabled': _redis_enabled,
        'local_connection_count': len(active_connections),
    }


def _send_to_user(user_id, payload_dict):
    """Send a JSON message to user's WebSocket (local or via Redis pub/sub)."""
    if user_id in active_connections:
        active_connections[user_id].send(json.dumps(payload_dict))
        return
    r = _get_redis_client()
    if r:
        try:
            r.publish(REDIS_WS_CHAN_PREFIX + user_id, json.dumps(payload_dict))
        except Exception:
            pass


# In-memory map of userId -> WebSocket. With Redis, "online" is shared across instances.
active_connections = {}
_user_pubsubs = {}
_user_pubsub_stop = {}


def _redis_subscriber_thread(user_id, ws):
    """Listen on Redis channel for this user and forward messages to ws."""
    if not _redis_url:
        return
    pubsub = None
    chan = REDIS_WS_CHAN_PREFIX + user_id
    try:
        import redis
        r = redis.from_url(_redis_url)
        pubsub = r.pubsub()
        pubsub.subscribe(chan)
        _user_pubsubs[user_id] = pubsub
        for msg in pubsub.listen():
            if msg['type'] == 'message':
                try:
                    ws.send(msg['data'].decode('utf-8') if isinstance(msg['data'], bytes) else msg['data'])
                except Exception:
                    break
            if msg['type'] == 'unsubscribe':
                break
            if _user_pubsub_stop.get(user_id):
                break
    except Exception:
        pass
    finally:
        if pubsub:
            try:
                pubsub.unsubscribe(chan)
                pubsub.close()
            except Exception:
                pass
        _user_pubsubs.pop(user_id, None)
        _user_pubsub_stop.pop(user_id, None)


@sock.route('/ws')
def ws_handler(ws):
    

    token = request.args.get('token')
    
    if not token:
        ws.send(json.dumps({'type': 'error', 'message': 'No token provided'}))
        return
    

    payload = verify_jwt_token(token)
    if not payload:
        ws.send(json.dumps({'type': 'error', 'message': 'Invalid token'}))
        return
    
    userId = payload.get('userId')
    active_connections[userId] = ws
    _log_app(f'ws_connect userId={userId[:12]}... connections_in_process={len(active_connections)}')
    r = _get_redis_client()
    if r:
        try:
            r.sadd(REDIS_ONLINE_KEY, userId)
        except Exception as e:
            _log_app(f'redis SADD failed on ws_connect: {e}')
        t = threading.Thread(target=_redis_subscriber_thread, args=(userId, ws), daemon=True)
        t.start()
    

    ws.send(json.dumps({'type': 'connected', 'userId': userId}))
    
    try:
        while True:

            message = ws.receive()
            if not message:
                break
            
            try:
                data = json.loads(message)
                message_type = data.get('type')
                

                if message_type == 'contact_request':
                    handle_contact_request_ws(ws, userId, data)
                elif message_type == 'contact_request_response':
                    handle_contact_request_response_ws(ws, userId, data)
                elif message_type == 'dh_init':
                    handle_dh_init_ws(ws, userId, data)
                elif message_type == 'dh_response':
                    handle_dh_response_ws(ws, userId, data)
                elif message_type == 'dh_finish':
                    handle_dh_finish_ws(ws, userId, data)
                elif message_type == 'send_message':
                    handle_send_message_ws(ws, userId, data)
                elif message_type == 'typing':
                    handle_typing_ws(ws, userId, data)
                else:
                    ws.send(json.dumps({'error': 'Unknown message type'}))
            except json.JSONDecodeError:
                ws.send(json.dumps({'error': 'Invalid JSON'}))
            except Exception as e:
                ws.send(json.dumps({'error': str(e)}))
    except:
        pass
    finally:
        r = _get_redis_client()
        if r:
            try:
                r.srem(REDIS_ONLINE_KEY, userId)
            except Exception:
                pass
            _user_pubsub_stop[userId] = True
            pubsub = _user_pubsubs.get(userId)
            if pubsub:
                try:
                    pubsub.unsubscribe(REDIS_WS_CHAN_PREFIX + userId)
                except Exception:
                    pass
        if userId in active_connections:
            del active_connections[userId]
            _log_app(f'ws_disconnect userId={userId[:12]}... connections_in_process={len(active_connections)}')


def handle_contact_request_ws(ws, fromUserId, data):
    
    toUserId = data.get('toUserId')
    if not toUserId:
        ws.send(json.dumps({'type': 'error', 'message': 'Missing toUserId'}))
        return
    

    if fromUserId == toUserId:
        ws.send(json.dumps({'type': 'error', 'message': 'Cannot send request to yourself'}))
        return
    

    to_user = User.query.filter_by(userId=toUserId).first()
    if not to_user:
        ws.send(json.dumps({'type': 'error', 'message': 'User not found'}))
        return
    

    existing = ContactRequest.query.filter(
        ContactRequest.fromUserId == fromUserId,
        ContactRequest.toUserId == toUserId,
        ContactRequest.status.in_(['pending', 'accepted'])
    ).first()
    
    if existing:
        ws.send(json.dumps({'type': 'error', 'message': 'Request already exists'}))
        return
    

    userA, userB = sorted([fromUserId, toUserId])
    chatId = f"{userA}_{userB}"
    existing_chat = Chat.query.filter_by(chatId=chatId).first()
    
    if existing_chat:
        ws.send(json.dumps({'type': 'error', 'message': 'Chat already exists with this user'}))
        return
    

    reverse_request = ContactRequest.query.filter(
        ContactRequest.fromUserId == toUserId,
        ContactRequest.toUserId == fromUserId,
        ContactRequest.status == 'pending'
    ).first()
    
    if reverse_request:

        chatId = get_chat_id_from_users(fromUserId, toUserId)
        

        if toUserId in active_connections:
            recipient_ws = active_connections[toUserId]
            recipient_ws.send(json.dumps({
                'type': 'contact_request_accepted',
                'chatId': chatId,
                'requestId': reverse_request.requestId,
                'reverseRequestId': contact_request.requestId,
                'initiator': fromUserId,
                'message': 'Mutual request detected - initiate key exchange'
            }))
        
        ws.send(json.dumps({
            'type': 'contact_request_accepted',
            'chatId': chatId,
            'requestId': contact_request.requestId,
            'reverseRequestId': reverse_request.requestId,
            'initiator': fromUserId,
            'message': 'Mutual request detected - initiate key exchange'
        }))
        return
    

    contact_request = ContactRequest(
        fromUserId=fromUserId,
        toUserId=toUserId,
        status='pending',
        createdAt=datetime.utcnow()
    )
    
    db.session.add(contact_request)
    db.session.commit()
    

    if toUserId in active_connections:
        recipient_ws = active_connections[toUserId]
        recipient_ws.send(json.dumps({
            'type': 'contact_request',
            'requestId': contact_request.requestId,
            'fromUserId': fromUserId
        }))
    

    ws.send(json.dumps({
        'type': 'contact_request_sent',
        'requestId': contact_request.requestId
    }))


def handle_contact_request_response_ws(ws, userId, data):
    
    requestId = data.get('requestId')
    action = data.get('action')
    
    if not requestId or action not in ['accept', 'reject']:
        ws.send(json.dumps({'type': 'error', 'message': 'Invalid request'}))
        return
    
    contact_request = ContactRequest.query.filter_by(
        requestId=requestId,
        toUserId=userId,
        status='pending'
    ).first()
    
    if not contact_request:
        ws.send(json.dumps({'type': 'error', 'message': 'Request not found'}))
        return
    
    if action == 'accept':

        reverse_request = ContactRequest.query.filter(
            ContactRequest.fromUserId == userId,
            ContactRequest.toUserId == contact_request.fromUserId,
            ContactRequest.status == 'pending'
        ).first()
        

        fromUserId = contact_request.fromUserId
        if not _is_user_online(fromUserId):
            ws.send(json.dumps({
                'type': 'error',
                'message': 'Other user is not online. Key exchange requires both users to be connected.'
            }))
            return
        

        chatId = get_chat_id_from_users(fromUserId, userId)
        
        if reverse_request:

            _send_to_user(fromUserId, {
                'type': 'contact_request_accepted',
                'chatId': chatId,
                'initiator': userId,
                'requestId': requestId,
                'reverseRequestId': reverse_request.requestId,
                'message': 'Mutual request detected - initiate key exchange'
            })

            ws.send(json.dumps({
                'type': 'contact_request_accepted',
                'chatId': chatId,
                'initiator': True,
                'requestId': requestId,
                'reverseRequestId': reverse_request.requestId,
                'message': 'Mutual request detected - initiate key exchange'
            }))
        else:
            _send_to_user(fromUserId, {
                'type': 'contact_request_accepted',
                'chatId': chatId,
                'initiator': userId,
                'requestId': requestId
            })

            ws.send(json.dumps({
                'type': 'contact_request_accepted',
                'chatId': chatId,
                'initiator': True,
                'requestId': requestId,
                'message': 'Contact request accepted. Initiate key exchange.'
            }))
    else:
        contact_request.status = 'rejected'
        contact_request.respondedAt = datetime.now(timezone.utc)
        db.session.commit()
        

        _send_to_user(contact_request.fromUserId, {
            'type': 'contact_request_rejected',
            'requestId': requestId
        })

        ws.send(json.dumps({
            'type': 'contact_request_rejected',
            'requestId': requestId
        }))


def handle_dh_init_ws(ws, fromUserId, data):
    
    chatId = data.get('chatId')
    toUserId = data.get('toUserId')
    dhPublicKeyJwk = data.get('dhPublicKeyJwk')
    nonce = data.get('nonce')
    signature = data.get('signature')
    
    if not all([chatId, toUserId, dhPublicKeyJwk, nonce, signature]):
        ws.send(json.dumps({'type': 'error', 'message': 'Missing required fields in dh_init'}))
        return
    




    expected_chatId = get_chat_id_from_users(fromUserId, toUserId)
    if chatId != expected_chatId:
        ws.send(json.dumps({'type': 'error', 'message': 'Invalid chatId - does not match user IDs'}))
        return
    
    if fromUserId == toUserId:
        ws.send(json.dumps({'type': 'error', 'message': 'Cannot send to yourself'}))
        return
    

    sender = User.query.filter_by(userId=fromUserId).first()
    if not sender:
        ws.send(json.dumps({'type': 'error', 'message': 'Sender not found'}))
        return
    

    if toUserId in active_connections:
        recipient_ws = active_connections[toUserId]
        forward_msg = {
            'type': 'dh_init',
            'chatId': chatId,
            'fromUserId': fromUserId,
            'dhPublicKeyJwk': dhPublicKeyJwk,
            'nonce': nonce,
            'signature': signature,
            'signPublicKeyJwk': sender.signPublicKeyJwk
        }

        if 'version' in data:
            forward_msg['version'] = data['version']
        recipient_ws.send(json.dumps(forward_msg))
    else:
        ws.send(json.dumps({'type': 'error', 'message': 'Recipient not connected'}))
        return
    

    ws.send(json.dumps({
        'type': 'dh_init_sent',
        'chatId': chatId
    }))


def handle_dh_response_ws(ws, fromUserId, data):
    
    chatId = data.get('chatId')
    toUserId = data.get('toUserId')
    dhPublicKeyJwk = data.get('dhPublicKeyJwk')
    nonce = data.get('nonce')
    signature = data.get('signature')
    
    if not all([chatId, toUserId, dhPublicKeyJwk, nonce, signature]):
        ws.send(json.dumps({'type': 'error', 'message': 'Missing required fields in dh_response'}))
        return
    




    expected_chatId = get_chat_id_from_users(fromUserId, toUserId)
    if chatId != expected_chatId:
        ws.send(json.dumps({'type': 'error', 'message': 'Invalid chatId - does not match user IDs'}))
        return
    
    if fromUserId == toUserId:
        ws.send(json.dumps({'type': 'error', 'message': 'Cannot send to yourself'}))
        return
    

    sender = User.query.filter_by(userId=fromUserId).first()
    if not sender:
        ws.send(json.dumps({'type': 'error', 'message': 'Sender not found'}))
        return
    

    if toUserId in active_connections:
        recipient_ws = active_connections[toUserId]
        forward_msg = {
            'type': 'dh_response',
            'chatId': chatId,
            'fromUserId': fromUserId,
            'dhPublicKeyJwk': dhPublicKeyJwk,
            'nonce': nonce,
            'signature': signature,
            'signPublicKeyJwk': sender.signPublicKeyJwk
        }

        if 'version' in data:
            forward_msg['version'] = data['version']
        recipient_ws.send(json.dumps(forward_msg))
    else:
        ws.send(json.dumps({'type': 'error', 'message': 'Recipient not connected'}))
        return
    

    ws.send(json.dumps({
        'type': 'dh_response_sent',
        'chatId': chatId
    }))


def handle_dh_finish_ws(ws, fromUserId, data):
    
    chatId = data.get('chatId')
    toUserId = data.get('toUserId')
    encryptedFinish = data.get('encryptedFinish')
    
    if not chatId or not toUserId or not encryptedFinish:
        ws.send(json.dumps({'type': 'error', 'message': 'Missing required fields in dh_finish'}))
        return
    




    expected_chatId = get_chat_id_from_users(fromUserId, toUserId)
    if chatId != expected_chatId:
        ws.send(json.dumps({'type': 'error', 'message': 'Invalid chatId - does not match user IDs'}))
        return
    
    if fromUserId == toUserId:
        ws.send(json.dumps({'type': 'error', 'message': 'Cannot send to yourself'}))
        return
    

    if toUserId in active_connections:
        recipient_ws = active_connections[toUserId]
        recipient_ws.send(json.dumps({
            'type': 'dh_finish',
            'chatId': chatId,
            'fromUserId': fromUserId,
            'encryptedFinish': encryptedFinish
        }))
    else:
        ws.send(json.dumps({'type': 'error', 'message': 'Recipient not connected'}))
        return
    

    ws.send(json.dumps({
        'type': 'dh_finish_sent',
        'chatId': chatId
    }))


@app.route('/api/chats/<chatId>/messages', methods=['GET'])
@require_auth
def get_chat_messages(chatId):
    
    try:
        userId = request.user_id
        

        chat = Chat.query.filter_by(chatId=chatId).first()
        if not chat or (chat.userA != userId and chat.userB != userId):
            return jsonify({'error': 'Chat not found or access denied'}), 404
        

        after_msg_id = request.args.get('after', None)
        

        query = Message.query.filter_by(chatId=chatId).order_by(Message.timestamp.desc()).limit(20)
        
        if after_msg_id:

            after_message = Message.query.filter_by(msgId=after_msg_id).first()
            if after_message:
                query = Message.query.filter_by(chatId=chatId).filter(Message.timestamp > after_message.timestamp).order_by(Message.timestamp.desc()).limit(20)
        
        messages = query.all()

        messages = list(reversed(messages))
        

        return jsonify({
            'messages': [{
                'msgId': msg.msgId,
                'chatId': msg.chatId,
                'sessionId': msg.sessionId,
                'senderId': msg.senderId,
                'timestamp': msg.timestamp.isoformat(),
                'ciphertext': msg.ciphertext,
                'iv': msg.iv,
                'ciphertext_len': msg.ciphertext_len,
                'isFile': msg.isFile if msg.isFile else False,
                'encryptedMetadata': {
                    'ciphertext': msg.encryptedMetadata,
                    'iv': msg.encryptedMetadataIv
                } if msg.isFile and msg.encryptedMetadata else None
            } for msg in messages]
        })
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@app.route('/api/chats/establish', methods=['POST'])
@require_auth
def establish_chat():
    
    try:
        data = request.get_json()
        chatId = data.get('chatId')
        requestId = data.get('requestId')
        reverseRequestId = data.get('reverseRequestId')
        
        if not chatId:
            return jsonify({'error': 'Missing chatId'}), 400
        
        userId = request.user_id
        


        otherUserId = None
        

        if requestId:
            request1 = ContactRequest.query.filter_by(requestId=requestId).first()
            if request1:
                otherUserId = request1.toUserId if request1.fromUserId == userId else request1.fromUserId
        if not otherUserId and reverseRequestId:
            request2 = ContactRequest.query.filter_by(requestId=reverseRequestId).first()
            if request2:
                otherUserId = request2.toUserId if request2.fromUserId == userId else request2.fromUserId
        

        if not otherUserId:
            pending_request = ContactRequest.query.filter(
                ((ContactRequest.fromUserId == userId) | (ContactRequest.toUserId == userId)),
                ContactRequest.status == 'pending'
            ).first()
            if pending_request:
                otherUserId = pending_request.toUserId if pending_request.fromUserId == userId else pending_request.fromUserId
        
        if not otherUserId:
            return jsonify({'error': 'Could not determine other user from requests'}), 400
        

        expected_chatId = get_chat_id_from_users(userId, otherUserId)
        if chatId != expected_chatId:
            return jsonify({'error': 'Invalid chatId - does not match user IDs'}), 400
        
        userA, userB = sorted([userId, otherUserId])
        

        request1 = None
        request2 = None
        
        if requestId:
            request1 = ContactRequest.query.filter_by(requestId=requestId).first()
        if reverseRequestId:
            request2 = ContactRequest.query.filter_by(requestId=reverseRequestId).first()
        

        if not request1:
            request1 = ContactRequest.query.filter(
                ((ContactRequest.fromUserId == userId) & (ContactRequest.toUserId == otherUserId)) |
                ((ContactRequest.fromUserId == otherUserId) & (ContactRequest.toUserId == userId)),
                ContactRequest.status == 'pending'
            ).first()
        

        create_chat_and_delete_requests(userA, userB, request1, request2)
        
        return jsonify({
            'ok': True,
            'chatId': chatId,
            'message': 'Chat established'
        })
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@app.route('/api/chats/<chatId>', methods=['DELETE'])
@require_auth
def delete_chat(chatId):
    
    try:
        userId = request.user_id
        

        chat = Chat.query.filter_by(chatId=chatId).first()
        if not chat:
            return jsonify({'error': 'Chat not found'}), 404
        
        if chat.userA != userId and chat.userB != userId:
            return jsonify({'error': 'Unauthorized'}), 403
        

        otherUserId = chat.userB if chat.userA == userId else chat.userA
        

        Message.query.filter_by(chatId=chatId).delete()
        

        db.session.delete(chat)
        
        db.session.commit()
        

        if otherUserId in active_connections:
            other_ws = active_connections[otherUserId]
            try:
                other_ws.send(json.dumps({
                    'type': 'chat_deleted',
                    'chatId': chatId,
                    'deletedBy': userId
                }))
            except Exception as e:
                pass
        
        return jsonify({
            'ok': True,
            'message': 'Chat deleted successfully'
        })
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


def handle_send_message_ws(ws, userId, data):
    
    chatId = data.get('chatId')
    encryptedMessage = data.get('encryptedMessage')
    sessionId = data.get('sessionId')
    
    if not chatId or not encryptedMessage:
        ws.send(json.dumps({'type': 'error', 'message': 'Missing chatId or encryptedMessage'}))
        return
    
    if not sessionId:
        ws.send(json.dumps({'type': 'error', 'message': 'Missing sessionId'}))
        return
    

    chat = Chat.query.filter_by(chatId=chatId).first()
    if not chat or (chat.userA != userId and chat.userB != userId):
        ws.send(json.dumps({'type': 'error', 'message': 'Chat not found or access denied'}))
        return
    

    recipientId = chat.userB if chat.userA == userId else chat.userA
    

    try:
        isFile = data.get('isFile', False)
        encryptedMetadata = data.get('encryptedMetadata')
        
        message = Message(
            chatId=chatId,
            sessionId=sessionId,
            senderId=userId,
            timestamp=datetime.now(timezone.utc),
            ciphertext=encryptedMessage.get('ciphertext', ''),
            iv=encryptedMessage.get('iv', ''),
            ciphertext_len=len(encryptedMessage.get('ciphertext', '')) if encryptedMessage.get('ciphertext') else None,
            isFile=isFile,
            encryptedMetadata=encryptedMetadata.get('ciphertext', '') if encryptedMetadata else None,
            encryptedMetadataIv=encryptedMetadata.get('iv', '') if encryptedMetadata else None
        )
        db.session.add(message)
        db.session.commit()
        msgId = message.msgId
    except Exception as e:
        db.session.rollback()
        ws.send(json.dumps({'type': 'error', 'message': f'Failed to store message: {str(e)}'}))
        return
    

    if recipientId in active_connections:
        recipient_ws = active_connections[recipientId]
        message_data = {
            'type': 'new_message',
            'chatId': chatId,
            'msgId': msgId,
            'sessionId': sessionId,
            'fromUserId': userId,
            'encryptedMessage': encryptedMessage,
            'timestamp': message.timestamp.isoformat()
        }

        if data.get('isFile'):
            message_data['isFile'] = True
            if data.get('encryptedMetadata'):
                message_data['encryptedMetadata'] = data.get('encryptedMetadata')
        recipient_ws.send(json.dumps(message_data))
    else:

        pass
    

    ws.send(json.dumps({
        'type': 'message_sent',
        'chatId': chatId,
        'msgId': msgId
    }))


def handle_typing_ws(ws, userId, data):
    
    chatId = data.get('chatId')
    
    if not chatId:
        ws.send(json.dumps({'type': 'error', 'message': 'Missing chatId'}))
        return
    

    chat = Chat.query.filter_by(chatId=chatId).first()
    if not chat or (chat.userA != userId and chat.userB != userId):
        ws.send(json.dumps({'type': 'error', 'message': 'Chat not found or access denied'}))
        return
    

    recipientId = chat.userB if chat.userA == userId else chat.userA
    

    if recipientId in active_connections:
        recipient_ws = active_connections[recipientId]
        recipient_ws.send(json.dumps({
            'type': 'typing',
            'chatId': chatId,
            'fromUserId': userId
        }))


@app.route('/api/account/delete', methods=['DELETE'])
@require_auth
def delete_account():
    
    try:
        userId = request.user_id
        

        ContactRequest.query.filter(
            (ContactRequest.fromUserId == userId) | (ContactRequest.toUserId == userId)
        ).delete()
        


        chats = Chat.query.filter(
            (Chat.userA == userId) | (Chat.userB == userId)
        ).all()
        

        other_user_ids = set()
        for chat in chats:
            other_user = chat.userB if chat.userA == userId else chat.userA
            other_user_ids.add(other_user)
        

        Chat.query.filter(
            (Chat.userA == userId) | (Chat.userB == userId)
        ).delete()
        

        user = User.query.filter_by(userId=userId).first()
        if user:
            db.session.delete(user)
        
        db.session.commit()
        

        for other_user_id in other_user_ids:
            if other_user_id in active_connections:
                other_ws = active_connections[other_user_id]
                try:
                    other_ws.send(json.dumps({
                        'type': 'user_deleted',
                        'deletedUserId': userId
                    }))
                except Exception as e:
                    pass
        

        if userId in active_connections:
            try:
                active_connections[userId].close()
            except:
                pass
            del active_connections[userId]
        

        Nonce.query.filter_by(userId=userId).delete()
        db.session.commit()
        
        return jsonify({
            'ok': True,
            'message': 'Account and all associated data deleted successfully'
        })
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


def cleanup_old_messages():
    
    try:
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=30)
        deleted_count = Message.query.filter(Message.timestamp < cutoff_date).delete()
        db.session.commit()
        return deleted_count
    except Exception as e:
        db.session.rollback()
        return 0


def cleanup_old_nonces():
    
    try:
        now_ms = int(time.time() * 1000)
        cutoff_ms = now_ms - (30 * 60 * 1000)
        
        deleted_count = Nonce.query.filter(Nonce.expiresAt < cutoff_ms).delete()
        db.session.commit()
        return deleted_count
    except Exception as e:
        db.session.rollback()
        return 0


@app.route('/api/logs', methods=['GET'])
def get_logs():
    """Return recent app log lines for the in-app /logs page."""
    lines = list(_app_log_buffer)
    return jsonify({'lines': lines})


@app.route('/api/debug', methods=['GET'])
def get_debug():
    """Return connection counts for this process and Redis (for /logs page)."""
    out = {
        'connections_in_this_process': len(active_connections),
        'redis_enabled': _redis_enabled,
    }
    r = _get_redis_client()
    if r:
        try:
            out['redis_online_count'] = r.scard(REDIS_ONLINE_KEY)
        except Exception as e:
            out['redis_error'] = str(e)
    else:
        out['redis_online_count'] = None
    return jsonify(out)


@app.route('/logs', methods=['GET'])
def logs_page():
    """Serve the in-app logs viewer page."""
    html = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Logs — nulla</title>
    <link rel="stylesheet" href="/css/main.css">
    <style>
        body { padding: 1rem 1.5rem; background: #0d0d0d; color: #e0e0e0; font-family: monospace; font-size: 13px; }
        .logs-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 1rem; flex-wrap: wrap; gap: 0.5rem; }
        .logs-title { font-size: 1.25rem; font-weight: 600; }
        .logs-refresh { color: #888; font-size: 12px; }
        .logs-pre { white-space: pre-wrap; word-break: break-all; margin: 0; padding: 1rem; background: #1a1a1a; border-radius: 6px; min-height: 200px; max-height: 70vh; overflow-y: auto; }
        .logs-pre .line { display: block; }
        .logs-pre .line.accept-fail { color: #f66; }
        .logs-pre .line.ws-connect { color: #6c6; }
        .logs-pre .line.ws-disconnect { color: #c96; }
        a { color: #88c; text-decoration: none; }
        a:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <div class="logs-header">
        <span class="logs-title">App logs</span>
        <span class="logs-refresh">Auto-refresh every 3s</span>
        <a href="/">← Back to app</a>
    </div>
    <div id="logs-debug" class="logs-debug" style="margin-bottom:0.5rem;font-size:12px;color:#888;"></div>
    <pre id="logs-pre" class="logs-pre">Loading…</pre>
    <script>
        const pre = document.getElementById('logs-pre');
        const debugEl = document.getElementById('logs-debug');
        function escapeHtml(s) {
            const div = document.createElement('div');
            div.textContent = s;
            return div.innerHTML;
        }
        function render(lines) {
            if (!lines || lines.length === 0) {
                pre.innerHTML = '<span class="line">No log entries yet.</span>';
                return;
            }
            pre.innerHTML = lines.map(line => {
                let cls = 'line';
                if (line.includes('requester not seen as online')) cls += ' accept-fail';
                else if (line.includes('ws_connect')) cls += ' ws-connect';
                else if (line.includes('ws_disconnect')) cls += ' ws-disconnect';
                return '<span class="' + cls + '">' + escapeHtml(line) + '</span>\\n';
            }).join('');
            pre.scrollTop = pre.scrollHeight;
        }
        function fetchLogs() {
            fetch('/api/logs')
                .then(r => r.json())
                .then(d => render(d.lines || []))
                .catch(() => { pre.textContent = 'Failed to load logs.'; });
        }
        function fetchDebug() {
            fetch('/api/debug')
                .then(r => r.json())
                .then(d => {
                    let t = 'This process: ' + d.connections_in_this_process + ' WebSocket(s)';
                    if (d.redis_enabled) {
                        t += ' | Redis online set: ' + (d.redis_online_count != null ? d.redis_online_count : '?') + ' user(s)';
                        if (d.redis_error) t += ' (error: ' + d.redis_error + ')';
                    }
                    debugEl.textContent = t;
                })
                .catch(() => { debugEl.textContent = 'Debug: failed to load'; });
        }
        fetchLogs();
        fetchDebug();
        setInterval(fetchLogs, 3000);
        setInterval(fetchDebug, 3000);
    </script>
</body>
</html>'''
    from flask import Response
    return Response(html, mimetype='text/html')


@app.route('/', methods=['GET'])
def index():
    
    frontend_dir = os.path.join(os.path.dirname(__file__), '..', 'frontend', 'html')
    return send_from_directory(frontend_dir, 'index.html')

@app.route('/<path:path>', methods=['GET'])
def serve_static(path):
    

    if path.startswith('api/') or path.startswith('ws'):
        return jsonify({'error': 'Not found'}), 404
    
    frontend_dir = os.path.join(os.path.dirname(__file__), '..', 'frontend')

    if '..' in path or path.startswith('/'):
        return jsonify({'error': 'Invalid path'}), 400
    return send_from_directory(frontend_dir, path)

with app.app_context():
    db.create_all()
    cleanup_old_messages()
    cleanup_old_nonces()

if __name__ == '__main__':
    host = os.environ.get('FLASK_HOST', '0.0.0.0')
    port = int(os.environ.get('PORT', os.environ.get('FLASK_PORT', '3000')))
    app.run(debug=False, host=host, port=port)