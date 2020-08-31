import firebase_admin
from firebase_admin import credentials
from firebase_admin import firestore
from datetime import datetime
try:
    import cryptobaker as cb
except ImportError:
    import pip
    pip.main(['install', 'cryptobaker'])
    import cryptobaker as cb
import os, json, base64

def from_env(name):
    enc = os.getenv(name)
    if enc:
        dec = base64.b64decode(enc).decode()
        conf = json.loads(dec)
        return credentials.Certificate(conf)

class DB(object):
    def __init__(self, creds):
        self.app = firebase_admin.initialize_app(creds)
        self.firestore = firestore.client(self.app)
        self.users = self.firestore.collection('users')
    
    def get_user(self, id):
        u = self.users.document(id)
        if u.get().exists:
            return u
    
    def hash(self, password: str):
        a = (cb.Dish(password) + 'lamee').apply(cb.toMD5)
        b = a.apply(cb.encode).apply(cb.toAscii85)
        return b.apply(cb.toSHA384).raw
    
    def date(self):
        return datetime.now()