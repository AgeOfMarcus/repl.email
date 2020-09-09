'''
YO RAFI

Basically I've moved to a new email host (the one that came with my domain marcusj.tech)
Its been forwarding there for a few days (and to the gmail too) but some older emails wont show up

Also sending email ive changed from smtp2go to sendgrid because sendgrid lets you send more, that seems to have gone smoothly

Okay fuck yes everything works well, now time to see if i can add more

IMPORTANT: sometimes the IMAP client breaks completely and just doesnt refresh, so I added in a JS function that should solve it, I've limited users to calling it once per minute cause it basically re-logs in to the imap server but i think it should fix errors. its fix_api()
'''

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
from replit import db
from imap_tools import (
    MailBox,
    A as ALL,
)
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail


from lib.wrap import get_profile

import os, uuid, requests, io, base64, logging

app = Flask(__name__)
CORS(app)
Mobility(app)
limiter = Limiter(
    app,
    key_func=lambda: session.get('user'),
)
app.config['SECRET_KEY'] = os.getenv('SECRET')

log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR) # shut up flask

mb = MailBox('imap.marcusj.tech').login(os.getenv('N_USER'), os.getenv('N_PASS'))
sg = SendGridAPIClient(os.getenv('SENDGRID_API_KEY'))

ALL_USERS = [(u + '@repl.email') for u in db.keys() if not u in ['forwards', 'flags', 'events']]

PROFILE_PICS = {}

SETTINGS = {
    'theme': ['dark', 'light'],
    'style': ['modern', 'classic'],
    'dateFormat': ['simple', 'detailed'],
    'signature': ['*Sent with [**repl.email**](https://repl.email)*']
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

@app.before_request
def app_before_request():
    if request.path.split('/')[-1] in ['', 'login', 'auth']:
        if session.get('user', False):
            return redirect('/app')

@app.route('/')
def app_test_index():
    return render_template('index.html', isMobile=request.MOBILE, MarcusWeinberger=pfp('MarcusWeinberger'), rafrafraf=pfp('rafrafraf'))

@app.route('/login')
def app_login():
    if 'k' in request.args:
        usern, apik = base64.b64decode(request.args['k']).decode().split(':')
        user = db.get(usern)
        if apik == user.get('api_key'):
            session['user'] = usern
            session['token'] = apik
            session['pfp'] = pfp(usern)
            return redirect('/app')
    return render_template('login.html', isMobile=request.MOBILE)

@app.route('/noreplauth', methods=['POST'])
def app_norepl_auth():
    username = request.form['user']
    apik = request.form['apik']

    user = db.get(username)
    if user:
        if apik == user.get('api_key'):
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
        user = db.get(user_name)
        if not user:
            db[user_name] = DEFAULT_SETTINGS
            #smtp.send(
            #    'MarcusWeinberger@repl.email',
            #    [user_name + '@repl.email'],
            #    'Welcome to repl.email!',
            #    text='Click the toggle HTML button to view this message',
            #    html=open('new_user.html','r').read(),
            #)
        user = db.get(user_name)

        session['user'] = user_name
        session['token'] = str(uuid.uuid4())
        session['pfp'] = pfp(user_name)
        session['theme'] = user.get('theme')
        return redirect('/app')

@app.route('/webhooks', methods=['POST'])
def app_webhooks():
    fw = db.get('forwards', {}).get(request.form['rcpt'], '').replace('@repl.email', '')
    if not fw == '' or fw == 'none':
        if '; ' in fw: fw = fw.split('; ')
        else: fw = [fw]
        sg.send(Mail(
            from_email = request.form.get('sender'),
            to_emails = fw,
            subject = request.form.get('subject'),
            html_content = '<h1>New Email</h1><h3><a href="https://repl.email/app">Click here to view</a></h3>'
        ))
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
        'open_settings': str(request.args.get('action') == 'settings').lower(),
        'dev_mode': str(request.args.get('dev') == 'true').lower()
    }
    if not user:
        return redirect('/login')
    
    if request.args.get('action') == 'compose':
        opts['compose_to'] = request.args.get('to', '').split(';')
        opts['compose_subject'] = request.args.get('subject', '')
        opts['compose_body'] = request.args.get('body', '')
        opts['compose_password'] = request.args.get('password', '')

    return render_template('webmail.html', user=user, token=token, pfp=session.get('pfp'), **db.get(user, {}), isMobile=request.MOBILE, **opts)

@app.route('/redirect')
def app_redirect():
    return render_template('redirect.html', url=request.args.get('url'))

@app.route('/settings')
def app_settings():
    return redirect('/app?action=settings')

@app.route('/tracking/<id>.png')
def app_tracking(id):
    if id in db['events']:
        db['events'] = {**db['events'], id: True}
        return base64.b64decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR4nGP6zwAAAgcBApocMXEAAAAASUVORK5CYII=')

# API


def api_auth(request, session):
    token = request.headers.get('token')
    if token:
        if token == session.get('token'):
            return True
        if token == session.get('api_key'):
            return True
    return False

def valid_ids(ids):
    return [str(id) for id in ids if not len([*mb.fetch(ALL(to=f'{session["user"]}@repl.email', uid=str(id)), headers_only=True)]) == 0]
def valid_dict(d):
    vids = valid_ids(list(d.keys()))
    return {i: d[i] for i in vids}

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

@app.route('/api/send', methods=['POST'])
def app_api_send():
    if api_auth(request, session):
        data = request.get_json()
        if data['to'][0].startswith('list:') and session['user'] in ['MarcusWeinberger', 'rafrafraf']:
            if data['to'][0] == 'list:all':
                data['to'] = ALL_USERS
        tracker = str(uuid.uuid4())
        db['events'] = {**db.get('events', {}), tracker: False}
        url = f'https://repl.email/tracking/{tracker}.png'
        message = Mail(
            from_email = f'{session["user"]}@repl.email',
            to_emails = data['to'],
            subject = data['subject'],
            html_content = data.get('html', data.get('text', '')) + f'<img id="tracking" src="{url}"/>',
        )
        if not data.get('send_at', 'none') == 'none':
            message.send_at = int(str(data['send_at'])[:10])
        res = sg.send(message)
        return str(res.status_code)
    return NO_AUTH()

@app.route('/api/tracking', methods=['POST'])
def api_tracking():
    if api_auth(request, session):
        id = request.get_json().get('id')
        return jsonify({'status': db['events'].get(id)})
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
        user = db.get(session['user'], {})
        ns = request.get_json().get('settings', {})
        vs = {k:v for k,v in ns.items() if v in SETTINGS[k]}
        db[session['user']] = {**user, **vs}
        return jsonify(db[session['user']])
    return NO_AUTH()

@app.route('/api/generate', methods=['POST'])
def app_api_generate():
    if api_auth(request, session):
        newkey = str(uuid.uuid4())
        db[session['user']] = {**db[session['user']], 'api_key': newkey}
        return newkey
    return NO_AUTH()

@app.route('/api/key', methods=['POST'])
def app_api_key():
    if api_auth(request, session):
        user = db.get(session['user'], {})
        return user.get('api_key', 'null')
    return NO_AUTH()

@app.route('/api/load', methods=['POST'])
def app_api_load():
    data = request.get_json()
    user = data['user']
    token = data['token']
    api_key = db.get(user, {}).get('api_key')
    if api_key and token == api_key:
        session['user'] = user
        session['token'] = token
        return 'ok'
    return 'err'

@app.route('/api/settings/forwards', methods=['POST'])
def app_api_settings_forwards():
    if api_auth(request, session):
        email = request.get_json().get('email', False)
        if email and email.endswith('@repl.email'): email = False
        fw = db.get('forwards', {}).get(session['user'])
        if email:
            db['forwards'] = {**db.get('forwards', {}), session['user']: email}
        return fw or ''
    return NO_AUTH()

@app.route('/api/settings/signature', methods=['POST'])
def app_api_settings_signature():
    if api_auth(request, session):
        sig = request.get_json().get('signature', 'none')
        if not sig == 'none':
            db['signature'] = {**db.get('signature', {}), session['user']: sig}
            return sig
        return db.get('signature', {}).get(session['user'], 'none')
    return NO_AUTH()

@app.route('/api/delete/forever', methods=['POST'])
def api_delete_forever():
    if api_auth(request, session):
        ids = valid_ids(request.get_json().get('ids', []))
        mb.delete(ids)
        return 'ok'

@limiter.limit('1 per minute')
@app.route('/api/relog', methods=['POST'])
def api_relog():
    if api_auth(request, session):
        globals()['mb'] = MailBox('imap.marcusj.tech').login(os.getenv('N_USER'), os.getenv('N_PASS'))
        return 'ok'
    return NO_AUTH()

@app.route('/api/get', methods=['POST'])
def apiv3_get():
    if api_auth(request, session):
        try:
            emails = [*mb.fetch(ALL(to=f'{session["user"]}@repl.email'))]
            return jsonify({
                msg.uid: {
                    'from': msg.from_,
                    'to': msg.to,
                    'subject': msg.subject,
                    'text': msg.text,
                    'html': msg.html,
                    'attatchments': [
                        {'filename': att.filename, 'filetype': att.content_type, 'data': base64.b64encode(att.payload).decode()} for att in msg.attachments
                    ],
                    'date': msg.date_str,
                    'flags': db.get('flags', {}).get(msg.uid, msg.flags),
                } for msg in emails
            })
        except Exception as e:
            print('err:',e)
            globals()['mb'] = MailBox('imap.marcusj.tech').login(os.getenv('N_USER'), os.getenv('N_PASS'))
            return redirect('/api/get')
    return NO_AUTH()

@app.route('/api/sent', methods=['POST'])
def api_sent():
    if api_auth(request, session):
        try:
            emails = [*mb.fetch(ALL(from_=f'{session["user"]}@repl.email'))]
            return jsonify({
                msg.uid: {
                    'from': msg.from_,
                    'to': msg.to,
                    'subject': msg.subject,
                    'text': msg.text,
                    'html': msg.html,
                    'attatchments': [
                        {'filename': att.filename, 'filetype': att.content_type, 'data': base64.b64encode(att.payload).decode()} for att in msg.attachments
                    ],
                    'date': msg.date_str,
                    'flags': ['SENT'],
                } for msg in emails
            })
        except Exception as e:
            print('err:',e)
            globals()['mb'] = MailBox('imap.marcusj.tech').login(os.getenv('N_USER'), os.getenv('N_PASS'))
            return redirect('/api/sent')
    return NO_AUTH()

@app.route('/api/delete', methods=['POST'])
def api_delete():
    if api_auth(request, session):
        id = request.get_json().get('id')
        if [*mb.fetch(ALL(to=f'{session["user"]}@repl.email', uid=id))]:
            d = db['flags'].get(id, [])
            d.append('DELETED')
            db['flags'] = {**db['flags'], id: d}
            return 'ok'
        return 'err'
    return NO_AUTH()

@app.route('/api/restore', methods=['POST'])
def api_restore():
    if api_auth(request, session):
        id = request.get_json().get('id')
        if [*mb.fetch(ALL(to=f'{session["user"]}@repl.email', uid=id))]:
            d = db['flags'].get(id, [])
            if 'DELETED' in d: d.remove('DELETED')
            db['flags'] = {**db['flags'], id: d}
            return 'ok'
        return 'err'
    return NO_AUTH()

@app.route('/api/flag', methods=['POST'])
def apiv3_flag():
    if api_auth(request, session):
        data = request.get_json() or {}
        valid = {}
        for uid, flags in data.items():
            if [*mb.fetch(ALL(to=f'{session["user"]}@repl.email', uid=uid))]:
                valid[uid] = flags
        if valid:
            db['flags'] = {**db['flags'], **valid}
        return jsonify(valid)
    return NO_AUTH()

@app.route('/api/flag/add', methods=['POST'])
def api_flag_add():
    if api_auth(request, session):
        data = request.get_json()
        ids = valid_ids(data.get('ids', []))
        flag = data.get('flag', False)

        if ids and flag:
            newflags = {}
            for id in ids:
                if not flag in (f:=db['flags'].get(id, [])):
                    newflags[id] = f
                    newflags[id].append(flag)
            db['flags'] = {**db['flags'], **newflags}
            return 'ok'
    return NO_AUTH()

@app.route('/api/flag/remove', methods=['POST'])
def api_flag_remove():
    if api_auth(request, session):
        data = request.get_json()
        ids = valid_ids(data.get('ids', []))
        flag = data.get('flag', False)

        if ids and flag:
            newflags = {}
            for id in ids:
                if flag in (f:=db['flags'].get(id, [])):
                    newflags[id] = f
                    newflags[id].remove(flag)
            db['flags'] = {**db['flags'], **newflags}
            return 'ok'
    return NO_AUTH()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)






# @rafrafraf was here
# @MarcusWeinberger was here 