import os
import pandas as pd
import requests
import firebase_admin
from firebase_admin import credentials, db
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, redirect, url_for, render_template
import threading
import schedule
import time
from flask_cors import CORS

# Withings API credentials
CLIENT_ID = '36eff5960dbee78d215040ff5cdc737edc2c6f6a8e12e6e24a6a699258be466d'
CLIENT_SECRET = 'f57f5bf2b8052719bc691b78d9d23631b9ddcce2b41d2f133daf62b64cd4182a'
REDIRECT_URI = 'http://162.19.243.243:5000/'
STATE = '11136964'

# Firebase credentials and initialization
cred = credentials.Certificate('credentials/healthy-676e4-firebase-adminsdk-9y97l-e1123b2c52.json')
firebase_admin.initialize_app(cred, {'databaseURL': 'https://healthy-676e4-default-rtdb.firebaseio.com'})

app = Flask(__name__)
CORS(app)
withings_api = None
authorization_code = None
email = None


class WithingsAPI:
    def __init__(self):
        self.client_id = CLIENT_ID
        self.client_secret = CLIENT_SECRET
        self.redirect_uri = REDIRECT_URI
        self.access_token = None
        self.refresh_token = None
        self.expires_in = None

    def get_authorization_url(self):
        return (
            f"https://account.withings.com/oauth2_user/authorize2"
            f"?response_type=code&client_id={self.client_id}&scope=user.info,user.metrics,user.activity"
            f"&redirect_uri={self.redirect_uri}&state={STATE}"
        )

    def request_access_token(self, authorization_code, email):
        token_url = 'https://wbsapi.withings.net/v2/oauth2'
        token_params = {
            'action': 'requesttoken',
            'grant_type': 'authorization_code',
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'code': authorization_code,
            'redirect_uri': self.redirect_uri,
        }
        response = requests.post(token_url, data=token_params)
        response_json = response.json()

        if response_json['status'] != 0:
            raise Exception(f"Error: {response_json}")

        # Extract tokens and expiration time
        self.access_token = response_json['body']['access_token']
        self.refresh_token = response_json['body']['refresh_token']
        self.expires_in = response_json['body']['expires_in']

        # Save these to Firebase
        user_ref = db.reference(f'/users/{email.replace(".", "_")}')
        user_ref.update({
            'access_token': self.access_token,
            'refresh_token': self.refresh_token,
            'expires_in': self.expires_in,
            'token_issue_time': datetime.utcnow().timestamp(),  # Store as a timestamp
        })

    def is_token_expired(self, expires_in):
        # Convert the expiration time to a datetime object
        expiration_datetime = datetime.utcfromtimestamp(expires_in)
        current_time = datetime.utcnow()
        return current_time >= expiration_datetime

    def refresh_access_token(self, client_id, client_secret, refresh_token):
        url = 'https://wbsapi.withings.net/v2/oauth2'
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
        }
        data = {
            'action': 'requesttoken',
            'client_id': client_id,
            'client_secret': client_secret,
            'grant_type': 'refresh_token',
            'refresh_token': refresh_token,
        }

        response = requests.post(url, headers=headers, data=data)

        if response.status_code == 200:
            data = response.json()
            new_access_token = data['body']['access_token']
            new_expiration_time = data['body']['expires_in']

            return new_access_token, new_expiration_time
        else:
            print(f"Error: {response.status_code}")
            print(response.text)
            return None, None

    def manage_access_token(self, email):
        user_ref = db.reference(f'/users/{email.replace(".", "_")}')
        access_token = user_ref.child('access_token').get()
        refresh_token = user_ref.child('refresh_token').get()
        expires_in = user_ref.child('expires_in').get()
        token_issue_time = user_ref.child('token_issue_time').get()

        if not token_issue_time:
            token_issue_time = datetime.utcnow().timestamp()

        access_token_expiration_time = token_issue_time + expires_in

        if self.is_token_expired(access_token_expiration_time):
            new_access_token, new_expiration_time = self.refresh_access_token(
                self.client_id, self.client_secret, refresh_token)

            if new_access_token and new_expiration_time:
                access_token = new_access_token
                expires_in = new_expiration_time
                token_issue_time = datetime.utcnow().timestamp()

                # Update tokens in Firebase
                user_ref.update({
                    'access_token': access_token,
                    'expires_in': expires_in,
                    'token_issue_time': token_issue_time
                })

                print(f"Using new access token: {access_token}")
            else:
                print("Failed to obtain a new access token.")
        else:
            print(f"Using current access token: {access_token}")

        self.access_token = access_token


@app.route('/')
def index():
    global authorization_code
    authorization_code = request.args.get('code')
    received_state = request.args.get('state')
    if authorization_code and received_state == STATE:
        return redirect(url_for('email_form'))
    else:
        auth_url = withings_api.get_authorization_url()
        return f'Please authorize the application by visiting this URL: <a href="{auth_url}">{auth_url}</a>'


@app.route('/email-form')
def email_form():
    return render_template('email_form.html')


@app.route('/send-email', methods=['POST'])
def send_email():
    global email
    email = request.form.get('email')
    if email:
        print(f"Received email: {email}")
        threading.Thread(target=process_withings_data, args=(email,)).start()
        return 'Thank you, you can close this window'
    else:
        return jsonify({'status': 'error', 'message': 'Email not provided'}), 400


def process_withings_data(email):
    global authorization_code
    try:
        withings_api.request_access_token(authorization_code, email)
        withings_api.manage_access_token(email)
        fetch_withings_data(email)
    except Exception as e:
        print(f"An error occurred during Withings data processing: {e}")


def fetch_withings_data(email):
    email = 'fatmanaifar1@gmail.com'
    user_ref = db.reference(f'/users/{email.replace(".", "_")}')
    withings_api.manage_access_token(email)
    access_token = withings_api.access_token

    headers = {'Authorization': 'Bearer ' + access_token}
    url_list = 'https://wbsapi.withings.net/v2/heart'
    data_list = {'action': 'list'}
    response_list = requests.post(url_list, headers=headers, data=data_list)
    if response_list.status_code == 200:
        result_list = response_list.json()
        ECG_list = result_list['body']['series']
        signal_ids = [ecg['ecg']['signalid'] for ecg in ECG_list]
        df_ecg_list = pd.json_normalize(ECG_list)
        url_get = 'https://wbsapi.withings.net/v2/heart'
        all_signal_data = []

        for signal_id in signal_ids:
            data_get = {'action': 'get', 'signalid': signal_id}
            response_get = requests.post(url_get, headers=headers, data=data_get)
            if response_get.status_code == 200:
                signal_data = response_get.json()
                all_signal_data.append(signal_data['body'])
            else:
                print(f"Error for Signal ID {signal_id}: {response_get.status_code}")
                print(response_get.text)

        df_all_signals = pd.json_normalize(all_signal_data)
        ECG_df = pd.merge(df_ecg_list, df_all_signals, left_index=True, right_index=True,
                          suffixes=('_ecg_list', '_ecg_data'))

        ECG_record = ECG_df[["ecg.signalid", "signal", "timestamp", "ecg.afib", "heart_rate.value"]]
        df_ECG_record = pd.DataFrame(ECG_record)
        df_ECG_record['timestamp'] = pd.to_datetime(df_ECG_record['timestamp'], unit='s')
        df_ECG_record['date'] = df_ECG_record['timestamp'].dt.strftime('%Y-%m-%d-%H-%M-%S')
        df_ECG_record = df_ECG_record.rename(
            columns={'ecg.signalid': 'signalId', 'timestamp': 'date', 'ecg.afib': 'afib',
                     'heart_rate.value': 'heart_rate'}).dropna()

        chunk_size = 5  # Adjust chunk size if necessary
        for start in range(0, len(df_ECG_record), chunk_size):
            chunk = df_ECG_record[start:start + chunk_size]
            ECG_dict = chunk.to_dict(orient='records')
            ECG = user_ref.child('ECG').child(str(start))
            ECG.set(ECG_dict)
    else:
        print(f"Error for ECGLIST API: {response_list.status_code}")
        print(response_list.text)
    print(f"Fetched and updated data for {email}")


def job():
    print("Fetching Withings data...")
    users_ref = db.reference('/users')
    users = users_ref.get()

    if users:
        for email in users.keys():
            fetch_withings_data(email.replace("_", "."))


# Schedule the job to run every 1 minute
#schedule.every(1).minutes.do(job)


def scheduler_thread():
    while True:
        schedule.run_pending()
        time.sleep(1)


# Start the scheduler thread
#threading.Thread(target=scheduler_thread).start()

if __name__ == '__main__':
    withings_api = WithingsAPI()
    port = int(os.getenv('PORT', 3200))  # Default to 3200 for local development
    host = os.getenv('HOST', '0.0.0.0')  # Default to '0.0.0.0' for accessibility in Docker and most cloud platforms
    app.run(host=host, port=port, debug=True)
