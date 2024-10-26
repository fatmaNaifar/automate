import os
from scipy.signal import resample, find_peaks
import scipy.signal as signal
import numpy as np
import pandas as pd
import requests
from flask import Flask, request, jsonify, redirect, url_for, render_template, Response
import paho.mqtt.client as mqtt
import json
from flask_cors import CORS

# ThingsBoard
THINGSBOARD_SERVER = "demo.thingsboard.io"
THINGSBOARD_PORT = 1883
topic = "v1/devices/me/telemetry"
def on_connect(client, userdata, flags, rc):
    if rc == 0:
        print("Connected to MQTT Broker!")
    else:
        print("Failed to connect, return code %d" % rc)
# Dictionary mapping device tokens to emails
devices = {
    "oZNvj6vCxxGzfdqEzlgM": "fatma.naifar@enis.tn",
    "Dqb4h08EqUgpFOouIFdq": "daad.airfit@gmail.com"
}

# Withings credentials
CLIENT_ID = '530c10aa63bec812521ab78e115616c405526d8301ed3a980c9c6de593163836'
CLIENT_SECRET = '5ef947ccc14d7195f066c9cb6fef8007113ce54e870acdd2d7fe83d5d60a6d32'
REDIRECT_URI = 'http://192.168.42.38:3200/authorize'
STATE = '11136964'
email = ''
app = Flask(__name__)
CORS(app)
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

def stream_normalized_segments(segments):
    """Streams normalized segments as a JSON response."""
    for segment in segments:
        normalized_segment = normalize_segment(segment).tolist()
        chunk = json.dumps({'segment': normalized_segment}) + '\n'
        yield chunk
        #time.sleep(0.1)
class WithingsAPI:
    def __init__(self):
        self.client_id = CLIENT_ID
        self.client_secret = CLIENT_SECRET
        self.redirect_uri = REDIRECT_URI
        self.access_token = None
        self.email = email

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
        global email
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

            # GET MEASURES (weight, height, heart pulse, SPO2, etc.)
            url = 'https://wbsapi.withings.net/measure'
            headers = {'Authorization': 'Bearer ' + self.access_token}
            data = {
                "action": "getmeas",
                "meastypes": '1,71,4,11,54,130,135,136,137,138',
                "category": 1,  # real measures
            }

            response = requests.post(url, headers=headers, data=data)

            if response.status_code == 200:
                result = response.json()
                measuregrps = result['body']['measuregrps']

                measures_list = []
                for measuregrp in measuregrps:
                    measures_list.extend(measuregrp['measures'])

                df_measures = pd.json_normalize(measures_list)
                df_SPO2 = df_measures[df_measures['type'] == 54].copy()  # Filter SPO2 data

                if not df_SPO2.empty:
                    SPO2_data = df_SPO2[["value"]].head(1).to_dict()
                    SPO2_value = list(SPO2_data["value"].values())[0]  # Extract the SPO2 value
                else:
                    SPO2_value = None  # Handle missing SPO2 data
                    print("No SPO2 data available.")

                device_id = first_row.get('deviceid')
                if device_id:
                    device_token = withings_api.get_device_token_by_email(email)
                    self.send_telemetry_data(device_token, first_row.to_dict())  # Send first row data
                    if SPO2_value:
                        self.send_telemetry_data(device_token, {"SPO2_value": SPO2_value})  # Send SPO2 data
                else:
                    print(f"No device token could be obtained for device ID: {device_id}")
            else:
                print(f"Error: {response.status_code} - {response.text}")

    def get_device_token_by_email(self, email):
        for token, user_email in devices.items():
            if user_email == email:
                return token
        return None

    def send_telemetry_data(self, device_token, telemetry_data):
        client = mqtt.Client()  # Use default MQTT version
        client.on_connect = on_connect
        print("Attempting to connect to ThingsBoard...")
        client.username_pw_set(device_token)  # Authenticate using device token
        client.connect(THINGSBOARD_SERVER, THINGSBOARD_PORT, 60)  # Connect to ThingsBoard MQTT broker
        client.loop_start()  # Start the loop to process MQTT events
        print(f"Sending telemetry for token {device_token}: {telemetry_data}")
        result = client.publish(topic, json.dumps(telemetry_data), qos=2)  # Publish telemetry data
        #result.wait_for_publish(5.0)
        #client.disconnect()
        print(f"Telemetry data sent to {device_token}")

withings_api = WithingsAPI()
# MQTT client setup
#client = mqtt.Client(protocol=mqtt.MQTTv5)  # Use MQTTv5 if supported, otherwise use MQTTv311 or MQTTv31
client = mqtt.Client()
client.connect(THINGSBOARD_SERVER, THINGSBOARD_PORT, 60)
@app.route('/')
def index():
    auth_url = withings_api.get_authorization_url()
    return f'Welcome! To authorize the app, visit: <a href="{auth_url}">{auth_url}</a>'

@app.route('/authorize', methods=['GET'])
@app.route('/authorization/<path:subpath>', methods=['GET'])
def authorize():
    authorization_code = request.args.get('code')
    state = request.args.get('state')

    if not authorization_code or state != STATE:
        return jsonify({'status': 'error', 'message': 'Authorization failed.'}), 400
    withings_api.request_access_token(authorization_code)
    withings_api.fetch_withings_data()
    return "<h1>Data fetched and telemetry sent successfully.</h1>"


@app.route('/send-email', methods=['POST'])
def receive_email():
    global email  # Use the global email variable
    data = request.get_json()
    email = data.get('email')
    if email:
        print(f"Email received: {email}")
        # Simply store the email and do nothing
        return jsonify({'status': 'success', 'message': 'Email stored successfully.'}), 200
    else:
        return jsonify({'status': 'error', 'message': 'Email is missing in the request.'}), 400
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
        return Response(stream_normalized_segments(segments), content_type='application/json')
    except Exception as e:
        import traceback
        print(f"Error: {e}")
        traceback.print_exc()
        return jsonify({'error': 'Server error'}), 500

if __name__ == '__main__':
    host = os.getenv('HOST', '0.0.0.0')
    app.run(host=host, port=3200, debug=True)
