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

## Versioning & Changelog

This repository uses Semantic Versioning with a pre-1.0 beta line (starting at `0.1.0`) and an automated GitHub changelog/release workflow.

- Version source: `__version__` in [__init__.py](__init__.py)
- Changelog: [CHANGELOG.md](CHANGELOG.md)
- Automation: [.github/workflows/release-please.yml](.github/workflows/release-please.yml)

To get clean automated changelogs, use Conventional Commit prefixes in PR titles or commit messages:

- `feat:` for new features
- `fix:` for bug fixes
- `docs:`, `chore:`, `refactor:`, `test:` for other updates
- Add `!` (for example `feat!:`) for breaking changes

For beta semantics (version `< 1.0.0`):

- `feat:` bumps minor (`0.x.0`)
- `fix:` bumps patch (`0.x.y`)
- breaking changes can still trigger major semantics when you decide to move to `1.0.0+`

## Notes

- `connect_mqtt` infers the AWS IoT endpoint from responses to `/user` and `/thing/{id}`. If Hydros introduces new field names, update `_infer_iot_endpoint` accordingly.
- `subscribe_thing_status` queues subscriptions until the MQTT connection is ready and automatically issues the LISTEN request.
- The example script at the bottom of `pyhydros.py` demonstrates a full interactive workflow.

## Infrastructure & Polling Politeness
This library interacts with the CoralVue/Hydros cloud infrastructure. To maintain the stability of these services for the entire community avoid pulling api at unreasonable rate (e.g more than every few minutes).

## License

Distributed under the terms of the MIT LICENSE file in this repository.

## ⚠️ Safety Warning & Disclaimer 

pyHydros is provided “as is” and “with all faults”, without warranty of any kind, express or implied. The author makes no representations or guarantees regarding safety, suitability, accuracy, reliability, availability, or fitness for any particular purpose.

This software is not designed, tested, or intended for safety-critical, life-supporting, or fail-safe control systems. Do not rely on this integration for life-critical functions (e.g. temperature control, circulation, oxygenation) or for scenarios where equipment failure could result in property damage (e.g. floods, electrical hazards, or fire).

Use of this software is entirely at your own risk. Improper configuration, software defects, network outages, cloud service changes, or unexpected behavior may result in equipment malfunction, property damage, or loss of aquatic life.

Always validate behavior in a controlled or non-critical environment before enabling automations. For critical functions, use Hydros’ native controller features, which are specifically designed with local control, redundancy, and safety safeguards.

In no event shall the author be liable for any direct, indirect, incidental, special, exemplary, or consequential damages arising from the use of, or inability to use, this software.

Nothing in this project constitutes professional, electrical, or safety advice.

This project is an independent, community-driven effort and is not affiliated with, authorized, maintained, or endorsed by CoralVue or Hydros. “Hydros” and “CoralVue” are trademarks of their respective owners and are used for identification purposes only.

