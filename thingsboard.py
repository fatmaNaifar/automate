import json
import math
import os

import requests
from flask import Flask, request, jsonify
import warnings
import pandas as pd
import logging
from tb_rest_client.rest_client_ce import *
from tb_rest_client.rest import ApiException
warnings.filterwarnings("ignore", category=DeprecationWarning)

# Withings API credentials
CLIENT_ID = '2ad04eab2ab7245ca5b7ec2f6f46776c9c49119fb317344acd2405f7b3dc238d'
CLIENT_SECRET = '848f11136dfbe1441b5cc970b06cf4dcc0bb9e9c483923b15ff50ced7382b2d4'
REDIRECT_URI = 'https://automate-caj6.onrender.com/authorize'
STATE = '11136964'

TB_ACCESS_TOKEN = 'eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJmYXRtYS5uYWlmYXJAZW5pcy50biIsInVzZXJJZCI6IjBiMjg4MTUwLTZmNzctMTFlZi05MjI5LWYzYWE1NzA2ODBmYiIsInNjb3BlcyI6WyJURU5BTlRfQURNSU4iXSwic2Vzc2lvbklkIjoiZDAzOTNiYjUtZTIwNi00ZWFiLWJmMmYtOTI2MDFiM2NkZWU5IiwiZXhwIjoxNzI3ODY3Mzg1LCJpc3MiOiJ0aGluZ3Nib2FyZC5pbyIsImlhdCI6MTcyNjA2NzM4NSwiZmlyc3ROYW1lIjoiRkFUTUEiLCJsYXN0TmFtZSI6Ik5BSUZBUiIsImVuYWJsZWQiOnRydWUsInByaXZhY3lQb2xpY3lBY2NlcHRlZCI6dHJ1ZSwiaXNQdWJsaWMiOmZhbHNlLCJ0ZW5hbnRJZCI6IjA4NTg0YTUwLTZmNzctMTFlZi05MjI5LWYzYWE1NzA2ODBmYiIsImN1c3RvbWVySWQiOiIxMzgxNDAwMC0xZGQyLTExYjItODA4MC04MDgwODA4MDgwODAifQ.x3dPE2XPgK6ZdpB89B2398DfSgBQSSMLoL9prBhpKKl5YbAczDWeJTMChhoWinLk-HrHLRQQlIuM_b7vZI7j3Q'
# ThingsBoard credentials
THINGSBOARD_HOST = 'demo.thingsboard.io'
TB_USERNAME = 'fatma.naifar@enis.tn'
TB_PASSWORD = 'neifar2024'
DEVICE_TOKENS={}
app = Flask(__name__)
withings_api = None
authorization_code = None
watch_id = None

# Configure logging
logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s - %(levelname)s - %(module)s - %(lineno)d - %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S')

# Initialize ThingsBoard REST client
rest_client = RestClientCE(base_url=f'http://{THINGSBOARD_HOST}')

class WithingsAPI:
    def __init__(self):
        self.client_id = CLIENT_ID
        self.client_secret = CLIENT_SECRET
        self.redirect_uri = REDIRECT_URI
        self.access_token = None

    def get_authorization_url(self):
        return (
            f"https://account.withings.com/oauth2_user/authorize2"
            f"?response_type=code&client_id={self.client_id}&scope=user.info,user.metrics,user.activity"
            f"&redirect_uri={self.redirect_uri}&state={STATE}"
        )

    def request_access_token(self, authorization_code):
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

        self.access_token = response_json['body']['access_token']

    def fetch_withings_data(self):
        headers = {'Authorization': 'Bearer ' + self.access_token}
        url_list = 'https://wbsapi.withings.net/v2/heart'
        data_list = {'action': 'list'}
        response_list = requests.post(url_list, headers=headers, data=data_list)

        if response_list.status_code == 200:
            result_list = response_list.json()
            ECG_list = result_list['body']['series']

            # Extract signal IDs and store in a list
            signal_ids = [ecg['ecg']['signalid'] for ecg in ECG_list]

            # Normalize the list of ECG series
            df_ecg_list = pd.json_normalize(ECG_list)

            # ECG GET endpoint
            url_get = 'https://wbsapi.withings.net/v2/heart'
            all_signal_data = []

            # Loop through each signal ID and fetch individual signal data
            for signal_id in signal_ids:
                data_get = {'action': 'get', 'signalid': signal_id}
                response_get = requests.post(url_get, headers=headers, data=data_get)

                if response_get.status_code == 200:
                    signal_data = response_get.json()
                    # Append the signal data to the list
                    all_signal_data.append(signal_data['body'])
                else:
                    print(f"Error for Signal ID {signal_id}: {response_get.status_code}")
                    print(response_get.text)

            # Normalize the list of signal data
            df_all_signals = pd.json_normalize(all_signal_data)

            # Merge the two DataFrames based on index
            ECG_df = pd.merge(df_ecg_list, df_all_signals, left_index=True, right_index=True,
                              suffixes=('_ecg_list', '_ecg_data'))
            #ECG_df['datetime'] = pd.to_datetime(ECG_df['timestamp'], unit='s')
            ECG_data =ECG_df[['deviceid','ecg.afib','heart_rate.value','signal','timestamp']]
            # Process each device ID
            # Select only the first row (index 0) of the DataFrame
            first_row = ECG_df[['deviceid', 'ecg.afib', 'heart_rate.value', 'signal', 'timestamp']].iloc[0]

            # Extract device ID from the first row
            device_id = first_row.get('deviceid')
            if device_id:
                # Get or create device token in ThingsBoard
                device_token = self.get_or_create_device(device_id)

                if device_token:
                    # Convert the first row to a dictionary for telemetry data
                    data_to_send = first_row.to_dict()

                    # Send telemetry data to ThingsBoard
                    self.send_telemetry_data(device_token, data_to_send)
                else:
                    print(f"No device token could be obtained for device ID: {device_id}")


        else:
            print(f"Error for ECGLIST API: {response_list.status_code}")
            print(response_list.text)

    def get_or_create_device(self, device_id):
        try:
            rest_client.login(username=TB_USERNAME, password=TB_PASSWORD)

            # List devices to check if it exists
            devices = rest_client.get_tenant_device_infos(page_size=10, page=0)
            for device in devices.data:
                if device.name == device_id:
                    # Return existing device ID if found
                    found_device = rest_client.get_device_by_id(DeviceId(device.id.id, 'DEVICE'))
                    TH_device_id = found_device.id.id
                    return TH_device_id

            # Create new device profile
            device_profile_id = "09e2e1f0-6f77-11ef-9229-f3aa570680fb"
            device = {
                "name": device_id,  # Name of your new device
                "type": "default",  # Or your chosen device type
                "deviceProfileId": {
                    "entityType": "DEVICE_PROFILE",
                    "id": device_profile_id  # Correctly specify the device profile ID here
                }
            }

            created_device = rest_client.save_device(device)
            logging.info(" Device was created:\n%r\n", device)
            # Return the ID of the newly created device
            TH_device_id = created_device.id.id  # Access the ID of the created device
            return TH_device_id
        except ApiException as e:
            logging.exception("Error in device management: %s", e)
            return None

    def clean_data(self,data):
        for key, value in data.items():
            if isinstance(value, float) and (math.isnan(value) or math.isinf(value)):
                data[key] = 0  # Replace with a default value or remove the key entirely
        return data

    '''def send_to_thingsboard(self, device_token, data):
        withings_api.clean_data(data)
        try:
            # Log in to the ThingsBoard REST API
            rest_client.login(username=TB_USERNAME, password=TB_PASSWORD)
            # Send the data as telemetry to ThingsBoard
            rest_client.save_device_attributes(device_token, 'SERVER_SCOPE', data)

            logging.info(f"Successfully sent data to ThingsBoard: {data}")

        except ApiException as e:
            logging.exception(f"Failed to send data to ThingsBoard: {e}")

        except ApiException as e:
            logging.exception(f"Failed to send data to ThingsBoard: {e}")'''

    def send_telemetry_data(self, device_id_str, telemetry_data):
        try:
            # Create an EntityId for the device with type 'DEVICE'
            device_id = DeviceId(id=device_id_str, entity_type="DEVICE")

            # Ensure telemetry data is cleaned and valid
            clean_data = self.clean_data(telemetry_data)
            # Define the telemetry scope
            scope = 'telemetry'
            # Send telemetry data using the save_entity_telemetry method
            rest_client.save_entity_telemetry(device_id, scope, clean_data)
            print("Telemetry data sent successfully.")

            rest_client.save_device_attributes(device_id, 'SERVER_SCOPE', device_id)
        except ApiException as e:
            print(f"Error sending telemetry: {e}")
@app.route('/')
def index():
    auth_url = withings_api.get_authorization_url()
    return f'Welcome to the Withings data processing server! To authorize the app, please visit this URL: <a href="{auth_url}">{auth_url}</a>'

@app.route('/authorize', methods=['GET'])
@app.route('/authorization/<path:subpath>', methods=['GET'])
def authorize():
    global authorization_code, watch_id
    authorization_code = request.args.get('code')
    received_state = request.args.get('state')

    if not authorization_code or received_state != STATE:
        auth_url = withings_api.get_authorization_url()
        return jsonify({'status': 'error', 'message': f'Authorization failed. Please visit this URL to try again: {auth_url}'}), 200

    # Match the watch_id based on DEVICE_TOKENS keys
    if authorization_code and received_state == STATE:
        watch_id = next((key for key, value in DEVICE_TOKENS.items()), None)  # Get any watch ID
        withings_api.request_access_token(authorization_code)
        withings_api.fetch_withings_data()
        return jsonify({'status': 'success', 'message': 'Authorization successful and data fetched.'}), 200

    return jsonify({'status': 'error', 'message': 'Invalid authorization code or state.'}), 400

if __name__ == '__main__':
    host = os.getenv('HOST', 'https://automate-caj6.onrender.com')
    app.run(host=host, port=10000, debug=True)
