# PyHydros - Quick Reference Guide

## Installation

```bash
uv pip install -r requirements.txt
```

## Setup

Create `.env` file with your credentials:
```
HYDROS_USERNAME=your_email@example.com
HYDROS_PASSWORD=your_password
```

## Quick Start

### 1. One-Time Data Access

```python
from pyhydros import HydrosAPI

client = HydrosAPI()
client.authenticate()

# Get Hydros
user = client.get_user()
hydros = user['things']

# Get Hydros details
hydros_id = hydros[0]['thingName']
hydros_details = client.get_thing(hydros_id)
print(f"Status: {hydros_details['connectionStatus']}")

# Get Hydros data
data = client.download_hydros_data_json(hydros_id)
```

**See example:** `example_simple.py`

### 2. Real-Time Streaming

```python
import time
from datetime import datetime

hydros_id = hydros[0]['thingName']
mqtt = client.connect_mqtt(thing_id=hydros_id)

def on_status(topic, payload):
    timestamp = datetime.utcnow().isoformat(timespec="seconds")
    print(f"[{timestamp}] {topic}: {payload}")

client.subscribe_thing_status(hydros_id, on_status)

print("Listening for updates. Press Ctrl+C to exit.")
try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    print("Stopping stream")
finally:
    if client.mqtt_client:
        client.mqtt_client.disconnect()
```

## API Reference

### Authentication
```python
client.authenticate()              # Login and get tokens
client.refresh_tokens()            # Refresh access token if expired
```

### Hydros
```python
client.get_user()                  # Get user and Hydros list
client.get_thing(thing_id)         # Get Hydros metadata/status
client.list_things()               # Quick list of Hydros IDs
client.update_thing(thing_id, {})  # Update Hydros config
```

### Hydros Data
```python
client.get_signed_url(thing_id)           # Get S3 signed URL
client.download_hydros_data(thing_id)     # Download Hydros data as bytes
client.download_hydros_data_json(thing_id) # Download Hydros data as JSON
```

### Real-Time Monitoring
```python
client.connect_mqtt(thing_id)                 # Establish AWS IoT MQTT session
client.subscribe_thing_status(thing_id, fn)   # Stream Hydros updates via callback
client.mqtt_client.publish(topic, payload)    # Optional: send commands/request data
client.mqtt_client.disconnect()               # Cleanly close connection when done
```

## Data Structures

### Hydros MQTT Data (S3)
```python
{
    "Input": {
        "Temp Probe A": {
            "type": "sense",
            "unitId": 1,
            "sensePort": "PORT_A1",
            "senseMode": "temp",
            "invisible": False,
            "minRange": "<min_temp_c>",
            "maxRange": "<max_temp_c>",
            "minGraphRange": "<graph_min_c>",
            "maxGraphRange": "<graph_max_c>",
            "alertLevel": "<alert_threshold>",
            "offset": "<calibration_offset>"
        }
    },
    "Output": {
        "Heater Channel 1": {
            "family": "temperature",
            "unitId": 1,
            "type": "heater",
            "onTemp": "<heater_on_c>",
            "offTemp": "<heater_off_c>",
            "input": "Temp Probe A",
            "input2": "<unused>",
            "outputDevice": "RELAY_A",
            "fallback": "<fallback_state>",
            "showAdvanced": False,
            "excludedModes": "<excluded_modes>",
            "dependency": "<unused>",
            "invisible": False,
            "minPower": "<min_watts>",
            "maxPower": "<max_watts>",
            "powerAlertLevel": "<power_alert_level>"
        },
        "Heater Channel 2": {
            "family": "temperature",
            "unitId": 2,
            "type": "heater",
            "onTemp": "<heater_on_c>",
            "offTemp": "<heater_off_c>",
            "input": "Temp Probe A",
            "input2": "<unused>",
            "fallback": "<fallback_state>",
            "showAdvanced": False,
            "excludedModes": "<excluded_modes>",
            "dependency": "<unused>",
            "invisible": False,
            "outputDevice": "<unused>"
        }
    },
    "Schedule": {},
    "Mode": {
        "Feeding": {
            "timeout": "<feeding_timeout_ms>",
            "color": "<feeding_color_code>",
            "type": "mode",
            "unitId": 1
        },
        "Normal": {
            "timeout": 0,
            "color": "<normal_color_code>",
            "readOnly": True,
            "type": "mode",
            "unitId": 2
        },
        "Water Change": {
            "timeout": 0,
            "color": "<water_change_color_code>",
            "type": "mode",
            "unitId": 3
        }
    },
    "WiFiOutlet": {},
    "TpDevice": {},
    "Option": {
        "Option": {
            "type": "OptionSet",
            "tempFmt": "<temp_format>",
            "volumeUnit": "<volume_unit>",
            "alkUnit": "<alk_unit>",
            "salinityUnit": "<salinity_unit>",
            "timeZoneRegion": "<tz_region>",
            "timeZoneCity": "<tz_city>",
            "timeZone": "<tz_identifier>",
            "modeControlInput": "<mode_input>",
            "ledMode": "<led_mode>",
            "partyType": 0,
            "ledOnTime": "<led_on_ms>",
            "ledOffTime": "<led_off_ms>",
            "lowPowerExitDelay": 0,
            "lowPower": "<unused>",
            "systemLog": False,
            "emailThreshold": "<email_alert_threshold>",
            "pushThreshold": "<push_alert_threshold>",
            "localThreshold": "<local_alert_threshold>",
            "alertRepeat": "<alert_repeat_ms>",
            "heartbeatTimeout": "<heartbeat_timeout_ms>",
            "pwEnable": False,
            "unitId": 1,
            "disableMonitoring": False,
            "alertLevel": "<option_alert_level>"
        }
    },
    "System": {
        "System": {
            "unitId": 1,
            "thingType": "Collective",
            "thingName": "COLLECTIVE_ID",
            "friendlyName": "Display Tank",
            "serialNum": "<system_serial>",
            "type": "System"
        }
    },
    "Device": {
        "1": {
            "type": "Device",
            "device": "DEVICE_ID_A",
            "collectiveName": "COLLECTIVE_ID",
            "unitId": 1,
            "wifiPriority": "<priority>",
            "thingType": "Controller",
            "friendlyName": "Controller A"
        },
        "2": {
            "type": "Device",
            "device": "DEVICE_ID_B",
            "collectiveName": "COLLECTIVE_ID",
            "wifiPriority": "<priority>",
            "unitId": 2,
            "thingType": "PowerBar",
            "friendlyName": "Controller B"
        }
    }
}
```


