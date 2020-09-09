import requests

def get_profile(username, apikey):
    try:
        res = requests.post("https://wrapapi.com/use/AgeOfMarcus/replit/pfp/0.0.1", json={
        'wrapAPIKey': apikey,
        'username': username,
    })
        return res.json()['data']['image'].split('"')[1]
    except Exception as e:
        print('fuck:', e)