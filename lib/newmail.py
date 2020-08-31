from smtp2go.core import Smtp2goClient
import email, quopri, imaplib, re

SMTP = Smtp2goClient

class Gmail(object):
    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.reload()
    
    def reload(self):
        self.client = imaplib.IMAP4_SSL('imap.gmail.com')
        self.client.login(self.username, self.password)
        self.client.select('inbox')
    def search(self, term, retry=True):
        try:
            status, data = self.client.search(None, 'X-GM-RAW', term)
            return [*map(int, data[0].decode().split())]
        except Exception as e:
            print('Connection error:', e)
            if not retry: return []
            self.reload()
            return self.search(term, retry=False)
    
    def get_gmail_labels(self, id):
        _, data = self.client.fetch(str(id), '(X-GM-LABELS)')
        return re.findall('"(.*?)"', data[0].decode())

    def set_gmail_labels(self, id, labels):
        old = [*self.get_gmail_labels(id)]
        if len(old) > 0:
            self.client.store(str(id), '-X-GM-LABELS', old)
        for label in labels:
            _, res = self.client.store(str(id), '+X-GM-LABELS', label)
        return re.findall('"(.*?)"', res[0].decode())

    def get(self, id, retry=True):
        try:
            typ, res = self.client.fetch(str(id), '(RFC822)')
            data = res[0][1]
            message = email.message_from_bytes(data)
            res = {
                'from': quopri.decodestring(message['From']).strip().decode(errors='ignore'),
                'to': message['To'],
                'subject': quopri.decodestring(message['Subject']).strip().decode(errors='ignore'),
                'date': message['Date'],
                'flags': [x.replace('\\', '') for x in self.get_gmail_labels(id)],
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