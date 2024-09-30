import os
import json
import math
import logging
import requests
import pandas as pd
import warnings
from flask import Flask, request, jsonify, Response
from flask_cors import CORS
from scipy.signal import resample, find_peaks
import scipy.signal as signal
import numpy as np
from tb_rest_client.rest_client_ce import *
from tb_rest_client.rest import ApiException
from scipy.signal import find_peaks

warnings.filterwarnings("ignore", category=DeprecationWarning)

# ThingsBoard and Withings credentials
CLIENT_ID = '530c10aa63bec812521ab78e115616c405526d8301ed3a980c9c6de593163836'
CLIENT_SECRET = '5ef947ccc14d7195f066c9cb6fef8007113ce54e870acdd2d7fe83d5d60a6d32'
REDIRECT_URI = 'http://airfit.redcad.org:5000/authorize'
STATE = '11136964'
TB_ACCESS_TOKEN ='eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJmYXRtYS5uYWlmYXJAZW5pcy50biIsInVzZXJJZCI6IjBiMjg4MTUwLTZmNzctMTFlZi05MjI5LWYzYWE1NzA2ODBmYiIsInNjb3BlcyI6WyJURU5BTlRfQURNSU4iXSwic2Vzc2lvbklkIjoiZDAzOTNiYjUtZTIwNi00ZWFiLWJmMmYtOTI2MDFiM2NkZWU5IiwiZXhwIjoxNzI3ODY3Mzg1LCJpc3MiOiJ0aGluZ3Nib2FyZC5pbyIsImlhdCI6MTcyNjA2NzM4NSwiZmlyc3ROYW1lIjoiRkFUTUEiLCJsYXN0TmFtZSI6Ik5BSUZBUiIsImVuYWJsZWQiOnRydWUsInByaXZhY3lQb2xpY3lBY2NlcHRlZCI6dHJ1ZSwiaXNQdWJsaWMiOmZhbHNlLCJ0ZW5hbnRJZCI6IjA4NTg0YTUwLTZmNzctMTFlZi05MjI5LWYzYWE1NzA2ODBmYiIsImN1c3RvbWVySWQiOiIxMzgxNDAwMC0xZGQyLTExYjItODA4MC04MDgwODA4MDgwODAifQ.x3dPE2XPgK6ZdpB89B2398DfSgBQSSMLoL9prBhpKKl5YbAczDWeJTMChhoWinLk-HrHLRQQlIuM_b7vZI7j3Q'

THINGSBOARD_HOST = 'demo.thingsboard.io'
TB_USERNAME = 'fatma.naifar@enis.tn'
TB_PASSWORD = 'neifar2024'
DEVICE_TOKENS = {}

app = Flask(__name__)
CORS(app)

# Initialize logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

# Initialize ThingsBoard REST client
rest_client = RestClientCE(base_url=f'http://{THINGSBOARD_HOST}')

# Function to resample ECG signal
def resample_ecg(ecg_signal, original_fs, target_fs):
    num_samples = int(len(ecg_signal) * (target_fs / original_fs))
    resampled_signal = resample(ecg_signal, num_samples)
    return resampled_signal

# Pan-Tompkins Algorithm for R peak detection
def pan_tompkins_detector(ecg_signal, sampling_rate):
    low_pass_b = np.array([1, 0, 0, 0, 0, 0, -2, 0, 0, 0, 0, 0, 1])
    low_pass_a = np.array([1, -2, 1])
    low_pass_filtered = signal.lfilter(low_pass_b, low_pass_a, ecg_signal)

    high_pass_b = np.array([-1.0 / 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1.0 / 32])
    high_pass_a = np.array([1, -1])
    high_pass_filtered = signal.lfilter(high_pass_b, high_pass_a, low_pass_filtered)

    derivative = np.diff(high_pass_filtered)
    squared = derivative ** 2
    window_size = int(0.150 * sampling_rate)
    integrated = np.convolve(squared, np.ones(window_size) / window_size, mode='same')

    threshold = np.mean(integrated) * 0.6
    peaks, _ = find_peaks(integrated, height=threshold, distance=sampling_rate / 5)

    return peaks

# Function to segment PQRST complexes
def segment_pqrst(ecg_signal, r_peaks, segment_length, window_before=0.2, window_after=0.4, sampling_rate=360):
    pqrst_segments = []
    for r_peak in r_peaks:
        start = int(r_peak - window_before * sampling_rate)
        end = int(r_peak + window_after * sampling_rate)
        segment = ecg_signal[start:end]
        if len(segment) < segment_length:
            segment = np.pad(segment, (0, segment_length - len(segment)), 'constant')
        elif len(segment) > segment_length:
            segment = segment[:segment_length]
        pqrst_segments.append(segment)
    return pqrst_segments

# Function to normalize segments
def normalize_segment(segment):
    mean = np.mean(segment)
    std = np.std(segment)
    if std == 0:
        return segment - mean  # Return the segment mean-centered only
    return (segment - mean) / std
# Withings API class to handle authorization and data fetching
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

            df_all_signals = pd.json_normalize(all_signal_data)
            ECG_df = pd.merge(df_ecg_list, df_all_signals, left_index=True, right_index=True)
            ECG_data = ECG_df[['deviceid', 'ecg.afib', 'heart_rate.value', 'signal', 'timestamp']]

            first_row = ECG_data.iloc[0]
            device_id = first_row.get('deviceid')
            if device_id:
                device_token = self.get_or_create_device(device_id)
                if device_token:
                    self.send_telemetry_data(device_token, first_row.to_dict())
                else:
                    print(f"No device token could be obtained for device ID: {device_id}")

    def get_or_create_device(self, device_id):
        try:
            rest_client.login(username=TB_USERNAME, password=TB_PASSWORD)
            devices = rest_client.get_tenant_device_infos(page_size=10, page=0)
            for device in devices.data:
                if device.name == device_id:
                    found_device = rest_client.get_device_by_id(DeviceId(device.id.id, 'DEVICE'))
                    return found_device.id.id

            device_profile_id = "09e2e1f0-6f77-11ef-9229-f3aa570680fb"
            device = {
                "name": device_id,
                "type": "default",
                "deviceProfileId": {
                    "entityType": "DEVICE_PROFILE",
                    "id": device_profile_id
                }
            }
            created_device = rest_client.save_device(device)
            return created_device.id.id
        except ApiException as e:
            logging.exception(f"Error in device management: {e}")
            return None

    def clean_data(self, data):
        for key, value in data.items():
            if isinstance(value, float) and (math.isnan(value) or math.isinf(value)):
                data[key] = 0
        return data

    def send_telemetry_data(self, device_id_str, telemetry_data):
        try:
            device_id = DeviceId(id=device_id_str, entity_type="DEVICE")
            clean_data = self.clean_data(telemetry_data)
            scope = 'telemetry'
            rest_client.save_entity_telemetry(device_id, scope, clean_data)
            rest_client.save_device_attributes(device_id, 'SERVER_SCOPE', device_id)
        except ApiException as e:
            logging.exception(f"Error sending telemetry: {e}")

withings_api = WithingsAPI()

@app.route('/')
def index():
    auth_url = withings_api.get_authorization_url()
    return f'Welcome! To authorize the app, visit: <a href="{auth_url}">{auth_url}</a>'
@app.route('/preprocess', methods=['POST'])
def preprocess():
    try:
        data = request.json
        if not data or 'signal' not in data:
            return jsonify({'error': 'Invalid input format'}), 400

        ecg_signal = np.array(data['signal'])
        sampling_rate = 360

        ecg_signal = resample_ecg(ecg_signal.tolist(), 100, sampling_rate)
        r_peaks = pan_tompkins_detector(ecg_signal, sampling_rate)
        segments = segment_pqrst(ecg_signal, r_peaks, 2160)

        def stream_normalized_segments():
            for segment in segments:
                normalized_segment = normalize_segment(segment).tolist()
                chunk = json.dumps({'segment': normalized_segment}) + '\n'
                yield chunk
                time.sleep(0.1)  # Simulate some processing delay if needed

        return Response(stream_normalized_segments(), content_type='application/json')

    except Exception as e:
        import traceback
        print(f"Error: {e}")
        traceback.print_exc()
        return jsonify({'error': 'Server error'}), 500
@app.route('/authorize', methods=['GET'])
def authorize():
    authorization_code = request.args.get('code')
    state = request.args.get('state')

    if not authorization_code or state != STATE:
        return jsonify({'status': 'error', 'message': 'Authorization failed.'}), 400

    withings_api.request_access_token(authorization_code)
    withings_api.fetch_withings_data()
    return jsonify({'status': 'success', 'message': 'Authorization successful and data fetched.'}), 200

if __name__ == '__main__':
    host = os.getenv('HOST', '0.0.0.0')
    app.run(host=host, port=10000, debug=True)
