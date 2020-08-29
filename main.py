from flask import (
    Flask,
    request,
    redirect,
    render_template,
    session,
    jsonify,
)
from flask_cors import CORS
from flask_mobility import Mobility
from flask_limiter import Limiter

from lib.db import DB, from_env
from lib.mail import SMTP, Gmail
from lib.wrap import get_profile

from google.api_core.exceptions import ResourceExhausted
import os, uuid, requests, io, base64

app = Flask(__name__)
CORS(app)
Mobility(app)
limiter = Limiter(
    app,
    key_func=lambda: session.get('user'),
)
app.config['SECRET_KEY'] = os.getenv('SECRET')

store = DB(from_env('CONF'))
smtp = SMTP(os.getenv('API'))
gmail = Gmail(os.getenv('GMAIL_USER'), os.getenv('GMAIL_PASS'))

try:
    ALL_USERS = [(u.id + '@repl.email') for u in store.users.get()]
except ResourceExhausted:
    ALL_USERS = []

PROFILE_PICS = {}

SETTINGS = {
    'theme': ['dark', 'light'],
    'style': ['modern', 'classic'],
    'dateFormat': ['simple', 'detailed'],
}

DEFAULT_SETTINGS = {k:v[0] for k,v in SETTINGS.items()}

def pfp(username):
    if username in PROFILE_PICS:
        return PROFILE_PICS[username]
    else:
        url = get_profile(username, os.getenv('WRAP'))
        PROFILE_PICS[username] = url
        return url

def upload_files(file):
    files = {
        '0': (file['filename'], io.BytesIO(base64.b64decode(file['data'])))
    }
    return requests.post('https://mediafire-proxy.marcusweinberger.repl.co', data={
        'key': os.getenv('MF_PROXY')
    }, files=files).json()['0']

# if gmail wont cooperate: https://accounts.google.com/b/0/DisplayUnlockCaptcha (if acc id is 0)

@app.before_request
def app_before_request():
    if request.path.split('/')[-1] in ['', 'login', 'auth']:
        if session.get('user', False):
            return redirect('/app')

@app.route('/')
def app_test_index():
    return render_template('index.html')


@app.route('/login')
def app_login():
    return render_template('login.html')

@app.route('/noreplauth', methods=['POST'])
def app_norepl_auth():
    username = request.form['user']
    apik = request.form['apik']

    user = store.get_user(username)
    if user:
        if apik == user.get().get('api_key'):
            session['user'] = username
            session['token'] = apik
            session['pfp'] = pfp(username)
            return redirect('/app')
    return redirect('/login')

@app.route('/auth')
def app_auth():
    user_id = request.headers.get('X-Replit-User-Id')
    user_name = request.headers.get('X-Replit-User-Name')

    if not user_id:
        return redirect('/login')
    else:
        user = store.get_user(user_name)
        if not user:
            store.users.document(user_name).set({
                'created': store.date(),
                **DEFAULT_SETTINGS,
            })
            smtp.send(
                'MarcusWeinberger@repl.email',
                [user_name + '@repl.email'],
                'Welcome to repl.email!',
                text='Click the toggle HTML button to view this message',
                html=open('new_user.html','r').read(),
            )

        session['user'] = user_name
        session['token'] = str(uuid.uuid4())
        session['pfp'] = pfp(user_name)
        session['theme'] = user.get().get('theme')
        return redirect('/app')


@app.route('/webhooks', methods=['POST'])
def app_webhooks():
    doc = store.firestore.collection('forwards').document(request.form.get('rcpt', '').replace('@repl.email', '')).get()
    if doc.exists and not doc.get('email') == 'none':
        addr = doc.get('email')
        if '; ' in addr: addr = addr.split('; ')
        else: addr = [addr]
        smtp.send(
            request.form.get('sender'),
            addr,
            request.form.get('subject'),
            html='<h1>New Email</h1><h3><a href="https://repl.email/app">Click here to view</a></h3>'
        )
    return ''

@app.route('/logout')
def app_logout():
    session.clear()
    return redirect('/')

@app.route('/app')
def app_webmail():
    user = session.get('user')
    token = session.get('token')
    opts = {
        'compose': str(request.args.get('action') == 'compose').lower(),
        'compose_to': [],
    }
    if not user:
        return redirect('/login')
    
    if request.args.get('action') == 'compose':
        opts['compose_to'] = request.args.get('to', '').split(';')
        opts['compose_subject'] = request.args.get('subject', '')
        opts['compose_body'] = request.args.get('body', '')
        opts['compose_password'] = request.args.get('password', '')

    return render_template('webmail.html', user=user, token=token, pfp=session.get('pfp'), **store.get_user(user).get().to_dict(), isMobile=request.MOBILE, **opts)

@app.route('/redirect')
def app_redirect():
    return render_template('redirect.html', url=request.args.get('url'))

@app.route('/settings')
def app_settings():
    user = session.get('user')
    token = session.get('token')
    if not user:
        return redirect('/login')
    return render_template('settings.html', user=user, token=token, pfp=session.get('pfp'), **store.get_user(user).get().to_dict(), isMobile=request.MOBILE)

# API


def api_auth(request, session):
    token = request.headers.get('token')
    if token:
        if token == session.get('token'):
            return True
        if token == session.get('api_key'):
            print('[api]:', session.get('user'))
            return True
    return False


def NO_AUTH():
    return jsonify({'err': 'missing token'})

@app.route('/api/profile', methods=['POST'])
def app_api_profile():
    if api_auth(request, session):
        return jsonify({'url':pfp(request.get_json().get('username', 'replit'))})
    return NO_AUTH()

@app.route('/api/contacts', methods=['POST'])
def app_api_fetch_contacts():
    if api_auth(request, session):
        return jsonify({'contacts': ALL_USERS})
    return NO_AUTH()

@app.route('/api/sent', methods=['POST'])
def app_api_sent():
    if api_auth(request, session):
        emails = gmail.search(f'from:{session["user"]}@repl.email')
        data = {i: gmail.get(i) for i in emails}
        return jsonify(data)
    return NO_AUTH()

@limiter.limit('100 per day')
@app.route('/api/send', methods=['POST'])
def app_api_send():
    if api_auth(request, session):
        data = request.get_json()
        if data['to'][0].startswith('list:') and session['user'] in ['MarcusWeinberger', 'rafrafraf']:
            if data['to'][0] == 'list:all':
                data['to'] = ALL_USERS
        payload = {
            'sender': session['user'] + '@repl.email',
            'recipients': data['to'], # [f'{session["user"]}+sent@repl.email', *data['to']],
            'subject': data.get('subject'),
            'text': data.get('text'),
            'html': data.get('html'),
        }
        res = smtp.send(**payload)
        return jsonify(res.json)
    return NO_AUTH()

@app.route('/api/upload', methods=['POST'])
def app_upload_file():
    if api_auth(request, session):
        file = request.get_json()
        return jsonify({'url':upload_files(file)})
    return NO_AUTH()

@app.route('/api/settings', methods=['POST'])
def app_api_settings():
    if api_auth(request, session):
        user = store.get_user(session['user'])
        ns = request.get_json().get('settings', {})
        for k, v in ns.items():
            if k in SETTINGS:
                if v in SETTINGS[k]:
                    user.update({k:v})
        return jsonify(user.get().to_dict())
    return NO_AUTH()

@app.route('/api/generate', methods=['POST'])
def app_api_generate():
    if api_auth(request, session):
        user = store.get_user(session['user'])
        newkey = str(uuid.uuid4())
        user.update({'api_key': newkey})
        return newkey
    return NO_AUTH()

@app.route('/api/key', methods=['POST'])
def app_api_key():
    if api_auth(request, session):
        user = store.get_user(session['user'])
        return user.get().to_dict().get('api_key', 'null')
    return NO_AUTH()

@app.route('/api/load', methods=['POST'])
def app_api_load():
    data = request.get_json()
    user = data['user']
    token = data['token']
    api_key = store.get_user(user).get().get('api_key')
    if token == api_key:
        session['user'] = user
        session['token'] = token
        return 'ok'
    return 'err'

@app.route('/api/settings/forwards', methods=['POST'])
def app_api_settings_forwards():
    if api_auth(request, session):
        email = request.get_json().get('email', False)
        if email and email.endswith('@repl.email'): email = False
        doc = store.firestore.collection('forwards').document(session['user'])
        if email:
            doc.set({
                'email': email,
            })
            return email
        if doc.get().exists:
            return doc.get().get('email')
        return ''
    return NO_AUTH()

@app.route('/api/settings/theme', methods=['POST'])
def app_api_settings_theme():
    if api_auth(request, session):
        user = store.get_user(session['user'])
        if (t:=request.get_json().get('theme')):
            if t in ['light', 'dark']:
                user.set({'theme':t})
                session['theme'] = t
                return t
        return session.get('theme', 'light')
    return NO_AUTH()

@app.route('/api/delete', methods=['POST'])
def app_api_delete():
    if api_auth(request, session):
        id = int(request.get_json()['id'])
        if id in gmail.search(f'to:{session["user"]}@repl.email'):
            gmail.client.set_gmail_labels(id, 'DELETED')
            return 'ok'
    return NO_AUTH()

@app.route('/api/delete/forever', methods=['POST'])
def app_api_real_delete():
    if api_auth(request, session):
        id = int(request.get_json()['id'])
        if id in gmail.search(f'to:{session["user"]}@repl.email'):
            gmail.client.delete_messages([id])
            gmail.client.expunge(messages=[id])
            return 'ok'
    return NO_AUTH()

@app.route('/api/get', methods=['POST'])
def app_api_get():
    if api_auth(request, session):
        emails = gmail.search(f'to:{session["user"]}@repl.email')[:request.get_json().get('num', -1)]
        data = {i: gmail.get(i) for i in emails}
        try:
            return jsonify(data)
        except Exception as e:
            print(e, ':', data)
            return jsonify({e:data}) # rafi did dis
    return NO_AUTH()

@app.route('/api/get/by/flag', methods=['POST'])
def app_api_get_by_flag():
    if api_auth(request, session):
        data = request.get_json()
        flag = data['flag']
        num = data.get('num', -1)
        emails = gmail.search(f'to:{session["user"]}@repl.email label:{flag}')[:num]
        return jsonify({i: gmail.get(i) for i in emails})
    return NO_AUTH()

@app.route('/api/flag', methods=['POST'])
def app_api_flag():
    if api_auth(request, session):
        data = request.get_json()
        data = {int(d):data[d] for d in data}
        emails = gmail.search(f'to:{session["user"]}@repl.email')
        if not all([id in emails for id in data.keys()]):
            return 'no'
        ndata = {
            id:[('\\' + x) for x in flags] for id,flags in data.items()
        }
        for id in ndata:
            gmail.client.set_gmail_labels(id, ndata[id])
        return 'ok'
    return NO_AUTH()

''''
@app.route('/api/flag', methods=['POST'])
def app_api_flag():
    if api_auth(request, session):
        data = request.get_json()
        ids = data.get('ids', [])
        if not type(ids) is list: ids = [ids]
        flags = [('\\' + x) for x in data.get('flags', [])]
        emails = gmail.search(f'to:{session["user"]}@repl.email')
        if not all([id in emails for id in ids]):
            return 'no'

        res = gmail.client.set_gmail_labels(ids, flags)
        return 'ok'
    return NO_AUTH()
'''

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)










# @rafrafraf was here
# @MarcusWeinberger was here 