# PyHydros

Python helper library for authenticating against Hydros via AWS Cognito, calling the REST API, and consuming real-time updates from AWS IoT MQTT.

## Features

- AWS Cognito username/password authentication with automatic region discovery.
- Automatic token refresh and header management for all REST calls.
- AWS IoT Device SDK (SigV4 over WebSockets) for MQTT with wildcard subscriptions.
- Zlib-aware payload decoding with header preservation for Hydros messages.
- Helpers for S3 signed URL retrieval and JSON decoding.
- Dedicated exception hierarchy for clearer error reporting.

## Installation

```bash
pip install -r requirements.txt
```

The project currently targets Python 3.9+. Required packages include `requests`, `boto3`, `python-dotenv`, `awscrt`, and `awsiot`.

## Configuration

Create a `.env` file alongside this repository with your Hydros credentials:

```
HYDROS_USERNAME=your@email
HYDROS_PASSWORD=your_password
```

## Usage

### Authenticate and Inspect Sensors

```python
from pyhydros import HydrosAPI

client = HydrosAPI()
client.authenticate()

profile = client.get_user()
print("User ID:", client.user_id)
print("Things:", [thing.get("thingName") for thing in profile.get("things", [])])
```

### Subscribe to Real-Time Updates

`connect_mqtt` now discovers the AWS IoT endpoint from the Hydros API responses and handles the Cognito Identity handshake automatically. Provide the Hydros thing id you wish to monitor:

```python
thing_id = profile["things"][0]["thingName"]
mqtt = client.connect_mqtt(thing_id=thing_id)

def handle_update(topic, payload):
    print("Topic:", topic)
    print("Payload:", payload)

client.subscribe_thing_status(thing_id, handle_update)
```

The helper publishes the required LISTEN request so that Hydros starts streaming status updates on the `/rsp/#` topic family. Incoming payloads are automatically decompressed, parsed as JSON, and annotated with `_hydros_header` when Hydros prepends header metadata.

### REST and S3 Helpers

```python
metadata = client.get_thing(thing_id)
signed_url = client.get_signed_url(thing_id)
config_json = client.download_hydros_data_json(thing_id)
```

All REST helpers call `_ensure_authenticated` first, guaranteeing valid tokens.

## Exception Model

- `HydrosAuthError`: Authentication and token refresh failures.
- `HydrosAPIError`: REST or S3 helper issues (for example, failed decompression).
- `HydrosMQTTError`: Problems establishing or using the MQTT connection (missing identity id, missing endpoint, publish/subscribe failures, etc.).

Catch these to provide targeted remediation guidance in your applications.

## Testing

Run the unit tests with the virtual environment activated:

```bash
python -m unittest -v
```

The suite covers token expiry logic, Cognito error propagation, MQTT precondition checking, dynamic region inference, and MQTT endpoint discovery edge cases.

## Notes

- `connect_mqtt` infers the AWS IoT endpoint from responses to `/user` and `/thing/{id}`. If Hydros introduces new field names, update `_infer_iot_endpoint` accordingly.
- `subscribe_thing_status` queues subscriptions until the MQTT connection is ready and automatically issues the LISTEN request.
- The example script at the bottom of `pyhydros.py` demonstrates a full interactive workflow.

## License

Distributed under the terms of the LICENSE file in this repository.

## ⚠️ Safety Warning & Disclaimer 

PyHydros is provided "as is" and "with all faults." The author makes no representations or warranties of any kind concerning the safety, suitability, or inaccuracies of this software.

Use at your own risk. Improper configuration or software bugs could lead to:

Equipment malfunction or fire.

Property damage (e.g., floods).

Loss of aquatic life.

Always test new configurations in a dry-run or controlled environment. This project is an independent community effort and is not affiliated with, authorized, maintained, or endorsed by CoralVue Hydros.

