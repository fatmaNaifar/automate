import json
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
CLIENT_ID = '2ad04eab2ab7245ca5b7ec2f6f46776c9c49119fb317344acd2405f7b3dc238d'
CLIENT_SECRET = '848f11136dfbe1441b5cc970b06cf4dcc0bb9e9c483923b15ff50ced7382b2d4'
REDIRECT_URI = 'https://automate-caj6.onrender.com'
STATE = '11136964'

# Path to the secret file in Render
secret_file_path = '/etc/secrets/FIREBASE_CREDENTIALS'

# Load credentials from the secret file
with open(secret_file_path, 'r') as f:
    firebase_credentials = f.read()

# Initialize Firebase with the credentials
cred_dict = json.loads(firebase_credentials)
cred = credentials.Certificate(cred_dict)
firebase_admin.initialize_app(cred, {'databaseURL': 'https://healthy-676e4-default-rtdb.firebaseio.com'})

app = Flask(__name__)
#CORS(app)
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

    def process_withings_data(self, email):
        global authorization_code
        try:
            self.request_access_token(authorization_code, email)
            self.manage_access_token(email)
            self.fetch_withings_data(email)  # Corrected this line
        except Exception as e:
            print(f"An error occurred during Withings data processing: {e}")

    def fetch_withings_data(self, email):
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

            # Limit to first two signals
            signal_ids_to_process = signal_ids[:2]

            for signal_id in signal_ids_to_process:
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

            chunk_size = 2  # Adjust chunk size if necessary
            for start in range(0, len(df_ECG_record), chunk_size):
                chunk = df_ECG_record[start:start + chunk_size]
                ECG_dict = chunk.to_dict(orient='records')
                ECG = user_ref.child('ECG').child(str(start))
                ECG.set(ECG_dict)
        else:
            print(f"Error for ECGLIST API: {response_list.status_code}")
            print(response_list.text)

        print(f"Fetched and updated data for {email}")

@app.route('/')
def index():
    auth_url = withings_api.get_authorization_url()
    return f'Welcome to the Withings data processing server! To authorize the app, please visit this URL: <a href="{auth_url}">{auth_url}</a>'


@app.route('/send-email', methods=['POST'])
def send_email():
    email = request.form.get('email')

    if email:
        # Store the email in Firebase
        email_ref = db.reference('/pending_authorization')
        email_ref.set({'email': email})

        print(f"Email received and stored: {email}")
        return jsonify({'status': 'success', 'message': 'Email received. Proceed to authorization.'}), 200
    else:
        return jsonify({'status': 'error', 'message': 'Email not provided'}), 400

@app.route('/authorization')
def authorization():
    global authorization_code
    authorization_code = request.args.get('code')
    received_state = request.args.get('state')

    # Retrieve the stored email from Firebase
    email_ref = db.reference('/pending_authorization')
    email_data = email_ref.get()

    if email_data:
        email = email_data.get('email')

    if not authorization_code or received_state != STATE:
        # Redirect user to the Withings authorization URL
        auth_url = withings_api.get_authorization_url()
        return jsonify({'status': 'error', 'message': f'Authorization failed. Please visit this URL to try again: {auth_url}'}), 200

    if authorization_code and received_state == STATE and email:
        print(f"Authorization received for email: {email}")

        # Process the Withings data for the given email
        withings_api.process_withings_data(email)

        # Clear the pending authorization for the user
        user_ref = db.reference(f'/users/{email.replace(".", "_")}')
        user_ref.child('pending_authorization').delete()

        # Clear the global pending authorization reference
        email_ref.delete()

        # Thank you message after successful authorization
        return '<h1>Thank you, authorization is successful. You can close this window now.</h1>'
    else:
        return 'Authorization failed or state mismatch. Please try again.'


withings_api = WithingsAPI()



# Start the scheduler thread
#threading.Thread(target=scheduler_thread).start()
if __name__ == '__main__':
    host = os.getenv('HOST', 'https://automate-caj6.onrender.com')
    app.run(host=host, port=10000, debug=True)