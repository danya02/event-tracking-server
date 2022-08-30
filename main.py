from flask import Flask, request, session, redirect, url_for, render_template, flash
from werkzeug.exceptions import HTTPException
from database import *
import time
import logging
import traceback

app = Flask(__name__)

stream_handler = logging.StreamHandler()
stream_handler.setLevel(logging.INFO)
app.logger.addHandler(stream_handler)

app.secret_key = SecretKey.get_secret()

@app.before_request
def before_request():
    db.connect()

@app.after_request
def after_request(response):
    db.close()
    return response

class UserError(Exception):
    def __init__(self, code, message):
        self.code = code
        self.message = message

@app.errorhandler(Exception)
def handle_exception(e):
    traceback.print_exception(type(e), e, e.__traceback__)
    return traceback.print_exception(type(e), e, e.__traceback__)


@app.route('/')
def index():
    if 'username' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/docs')
def docs():
    return render_template('docs.html')

def get_user():
    if 'username' in session:
        return User.select().where(User.username == session['username']).get()
    else:
        return None

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    user = User.select().where(User.username == username).get_or_none()
    if user:
        if user.check_password(password):
            session['username'] = username
            return redirect(url_for('dashboard'))
    flash('Invalid username or password')
    return redirect(url_for('index'))

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('index'))

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('index'))
    user = get_user()
    streams = list(user.streams)
    latest_changes = dict()
    for stream in streams:

        latest_event = stream.events.order_by(Event.unix_millis.desc()).limit(1).get_or_none()
        if not latest_event:
            latest_changes[stream.id] = 'No events'
        else:
            ctime = time.ctime(latest_event.unix_millis/1000)
            latest_changes[stream.id] = f"{ctime} into {latest_event.new_state} from {latest_event.by_ip}"
    return render_template('dashboard.html', streams=streams, latest_changes=latest_changes)

@app.route('/streams/new', methods=['POST'])
def create_stream():
    user = get_user()
    if not user:
        raise UserError(401, 'Not logged in')
    name = request.form['name']
    is_stateful = request.form.get('stateful') == 'true'
    expected_states = request.form['states']
    stream = EventStream.create(owner=user, name=name, is_stateful=is_stateful, expected_states=expected_states, password=secrets.token_urlsafe(16))
    return redirect(url_for('dashboard'))

@app.route('/streams/<stream>/delete', methods=['POST'])
def delete_stream(stream):
    user = get_user()
    if not user:
        raise UserError(401, 'Not logged in')
    stream = EventStream.select().where(EventStream.name == stream).get_or_none()
    if stream and stream.owner == user:
        Event.delete().where(Event.stream == stream).execute()
        stream.delete_instance()
        return 'Deleted OK'
    if not stream:
        raise UserError(404, 'Stream not found')
    raise UserError(403, 'Stream not owned by you')


@app.route('/api/submit-post/<path:path>', methods=['POST'])
def submit_post(path):
    stream_name = None
    password = None
    state = None

    # Figure out the return format and whether we are doing a dry run.
    action = path.split('/')[-1]
    if action in ['dryrun', 'test']:
        dry_run = True
    elif action in ['do', 'run', 'create']:
        dry_run = False
    else:
        raise UserError(400, f'Invalid action: {action}')


    # 1. Parse the POST data, if available
    try:
        if request.json:
            stream_name = stream_name or request.json.get('stream_name')
            password = password or request.json.get('password')
            state = state or request.json.get('state')
    except: pass  # werkzeug.exceptions.BadRequest: 400 Bad Request: Did not attempt to load JSON data because the request Content-Type was not 'application/json'.

    # 2. Use the headers
    stream_name = stream_name or request.headers.get('X-Event-Stream')
    password = password or request.headers.get('X-ES-Password')
    state = state or request.headers.get('X-ES-State')

    # 3. Use the query params
    stream_name = stream_name or request.args.get('stream')
    password = password or request.args.get('password')
    state = state or request.args.get('state')

    # 4. Use the path
    path = path.split('/')
    for first, second in zip(path[0::2], path[1::2]):
        if first == 'stream':
            stream_name = stream_name or second
        elif first == 'password':
            password = password or second
        elif first == 'state':
            state = state or second
    
    if not stream_name:
        raise UserError(400, 'Missing stream name')
    if not password:
        raise UserError(400, 'Missing password')
    if not state:
        raise UserError(400, 'Missing state')

    stream = EventStream.select().where(EventStream.name == stream_name).get_or_none()
    if not stream:
        raise UserError(404, 'Stream not found')
    if not stream.password == password:
        raise UserError(401, 'Invalid password')

    if not dry_run:
        e: Event = Event()
        e.stream = stream
        e.new_state = state if stream.is_stateful else None
        e.by_ip = request.remote_addr
        e.unix_millis = int(time.time() * 1000)
        e.save()
    
    return 'ok'

@app.route('/api/submit-get/<path:path>', methods=['GET'])
def submit_get(path):
    return submit_post(path)
