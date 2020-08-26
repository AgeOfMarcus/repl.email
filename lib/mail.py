from smtp2go.core import Smtp2goClient
from imapclient import IMAPClient
import email, quopri

# https://stackoverflow.com/questions/2182196/how-do-i-reply-to-an-email-using-the-python-imaplib-and-include-the-original-mes

SMTP = Smtp2goClient

class Gmail(object):
    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.client = IMAPClient('imap.gmail.com', use_uid=True, ssl=True)
        self.client.login(username, password)
        self.client.select_folder('INBOX')
    
    def reload(self):
        self.client = IMAPClient('imap.gmail.com', use_uid=True, ssl=True)
        self.client.login(self.username, self.password)
        self.client.select_folder("INBOX")

    def search(self, term, retry=True):
        try:
            return self.client.gmail_search(term)
        except Exception as e:
            print('Connection error:', e)
            if not retry: return []
            self.reload()
            return self.search(term, retry=False)
    
    def fields(self, field):
        ftype = field.get_content_type().split('/')[0]
        pl = field.get_payload()
        if type(pl) == bytes:
            return {ftype:pl.decode(errors="ignore")}
        elif type(pl) == str:
            return {ftype:pl}
        elif type(pl) == list:
            res = {}
            for subfield in pl:
                res.update(self.fields(subfield))
            return res
        else:
            return {ftype:str(pl)}
    
    def get(self, id, retry=True):
        try:
            data = self.client.fetch(id, ['RFC822'])[id][b'RFC822']
            message = email.message_from_bytes(data)
            res = {
                'from': quopri.decodestring(message['From']).strip().decode(errors='ignore'),
                'to': message['To'],
                'subject': quopri.decodestring(message['Subject']).strip().decode(errors='ignore'),
                'date': message['Date'],
                'flags': [x.replace('\\', '') for x in self.client.get_gmail_labels(id)[id]],
                'files': [],
            }
            if message.is_multipart():
                for part in message.walk():
                    ctype = part.get_content_type()
                    if ctype == 'text/html':
                        res['html'] = quopri.decodestring(part.get_payload()).strip().decode(errors="ignore")
                    elif ctype == 'text/plain':
                        res['text'] = quopri.decodestring(part.get_payload()).strip().decode(errors="ignore")
                    elif ctype.startswith('multipart'):
                        pass
                    else:
                        try:
                            res['files'].append({
                                'filename': part.get_filename(),
                                'filetype': part.get_content_type(),
                                'data': part.get_payload(),
                            })
                        except:
                            res[ctype] = part.get_payload()
            else:
                ctype = message.get_content_type()
                if ctype == 'text/html':
                    res['html'] = quopri.decodestring(message.get_payload()).strip().decode(errors="ignore")
                elif ctype == 'text/plain':
                    res['text'] = quopri.decodestring(message.get_payload()).strip().decode(errors="ignore")
                else:
                    try:
                        res['files'].append({
                            'filename': part.get_filename(),
                            'filetype': part.get_content_type(),
                            'data': part.get_payload(),
                        })
                    except:
                        res[ctype] = part.get_payload()
            return res
        except Exception as e:
            print('Connection error (get):', e)
            if not retry: return {}
            self.reload()
            return self.get(id, retry=False)