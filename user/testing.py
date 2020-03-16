import requests
from user import cp_host, service_host, ap_host

from time import process_time 

user_host = "user"

def setup_policies():
    data = {
        'interval': 120,
        'lifetime': 120,
        'description': 'test'
    }
    res = requests.post("http://%s:5000/gen_policies" % cp_host, data=data)
    params = {
        'max_age': 120,
        'description': 'test'
    }
    res = requests.post("http://%s:5000/gen_policies" % ap_host, data=data)

def login():
    data = {
        'email': 'random@random.com',
        'name': 'random',
        'password': '123456'
    }
    res = requests.post("http://%s:5000/signup" % user_host, data=data)
    data = {
        'email': 'random@random.com',
        'password': '123456'
    }
    res = requests.post("http://%s:5000/login" % user_host, data=data)

def generate_keys():
    data = {
        'number': 1,
        'time': '16/03/2020 12:00',
        'policy': 1
    }
    res = requests.post("http://%s:5000/generate_keys" % user_host, data=data)

def publish_policies(time):
    data = {
        'timestamp': time,
        'policy': 1
    }
    res = requests.post("http://%s:5000/publish_policies" % cp_host, data=data)
    return res.status_code

def verify(time):
    data = {
        'cp': 2000,
        'timestamp': time,
        'policy': 1
    }
    res = requests.post("http://%s:5000/access_service" % user_host, data=data)

if __name__ == "__main__":
    setup_policies()
    login()
    generate_keys()
    while(publish_policies('16/03/2020 12:00') >= 500):
        pass
    verify('16/03/2020 12:00')
