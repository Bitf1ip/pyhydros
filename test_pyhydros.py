"""Test suite for PyHydros library."""

import base64
import json
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

from botocore.exceptions import ClientError

from pyhydros import (
    AuthTokens,
    CognitoSRPAuth,
    HydrosAPI,
    HydrosAPIError,
    HydrosAuthError,
    HydrosDosingLogEntry,
    HydrosMQTTError,
    MQTTClient,
)


class TestAuthTokens(unittest.TestCase):
    """Test AuthTokens expiration handling."""

    def test_token_not_expired(self):
        tokens = AuthTokens(
            access_token="test_access",
            id_token="test_id",
            refresh_token="test_refresh",
            expires_in=3600,
            issued_at=datetime.utcnow(),
        )
        self.assertFalse(tokens.is_expired())

    def test_token_expired(self):
        issued = datetime.utcnow() - timedelta(seconds=4000)
        tokens = AuthTokens(
            access_token="test_access",
            id_token="test_id",
            refresh_token="test_refresh",
            expires_in=3600,
            issued_at=issued,
        )
        self.assertTrue(tokens.is_expired())

    def test_token_without_issue_time(self):
        tokens = AuthTokens(
            access_token="test_access",
            id_token="test_id",
            refresh_token="test_refresh",
        )
        self.assertFalse(tokens.is_expired())


class TestCognitoSRPAuth(unittest.TestCase):
    """Test Cognito authentication helpers."""

    def setUp(self):
        client_patcher = patch("pyhydros.boto3.client")
        self.addCleanup(client_patcher.stop)
        self.mock_client_factory = client_patcher.start()
        self.mock_idp_client = self.mock_client_factory.return_value

        self.auth = CognitoSRPAuth("user@example.com", "ExamplePassword123!")

    def test_initial_region(self):
        self.assertEqual(self.auth.region, "us-west-2")
        self.mock_client_factory.assert_called_with("cognito-idp", region_name="us-west-2")

    def test_set_region_reinitializes_client(self):
        self.auth.set_region("eu-central-1")
        self.assertEqual(self.auth.region, "eu-central-1")
        self.mock_client_factory.assert_called_with("cognito-idp", region_name="eu-central-1")

    def test_authenticate_client_error_raises_hydrosautherror(self):
        self.mock_idp_client.initiate_auth.side_effect = ClientError(
            {"Error": {"Code": "NotAuthorizedException", "Message": "nope"}},
            "InitiateAuth",
        )
        with self.assertRaises(HydrosAuthError):
            self.auth.authenticate()

    def test_refresh_token_client_error_raises_hydrosautherror(self):
        self.mock_idp_client.initiate_auth.side_effect = ClientError(
            {"Error": {"Code": "NotAuthorizedException", "Message": "nope"}},
            "InitiateAuth",
        )
        with self.assertRaises(HydrosAuthError):
            self.auth.refresh_token("refresh")


class TestMQTTClient(unittest.TestCase):
    """Test MQTT helper behaviors."""

    def test_publish_without_connection_raises(self):
        client = MQTTClient("example-ats.iot.us-west-2.amazonaws.com")
        with self.assertRaises(HydrosMQTTError):
            client.publish("topic/test", {"ping": True})

    def test_build_credentials_without_session_credentials(self):
        session = MagicMock()
        session.get_credentials.return_value = None
        client = MQTTClient("example-ats.iot.us-west-2.amazonaws.com")
        with self.assertRaises(HydrosMQTTError):
            client._build_credentials_provider(session)


class TestHydrosAPI(unittest.TestCase):
    """Test HydrosAPI convenience methods."""

    def setUp(self):
        client_patcher = patch("pyhydros.boto3.client")
        session_patcher = patch("pyhydros.boto3.Session")
        self.addCleanup(client_patcher.stop)
        self.addCleanup(session_patcher.stop)
        self.mock_boto_client = client_patcher.start()
        session_patcher.start()

        self.api = HydrosAPI("user@example.com", "ExamplePassword123!")

    @staticmethod
    def _build_token(region: str = "us-west-2") -> str:
        header = base64.urlsafe_b64encode(json.dumps({"alg": "none"}).encode()).decode().rstrip("=")
        payload_data = {
            "iss": f"https://cognito-idp.{region}.amazonaws.com/{region}_abc",
        }
        payload = base64.urlsafe_b64encode(json.dumps(payload_data).encode()).decode().rstrip("=")
        return f"{header}.{payload}.signature"

    def test_update_region_from_token_updates_auth_client(self):
        self.api.auth.set_region = MagicMock()
        token = self._build_token("eu-central-1")
        self.api._update_region_from_token(token)
        self.assertEqual(self.api.region, "eu-central-1")
        self.api.auth.set_region.assert_called_once_with("eu-central-1")

    def test_update_region_from_endpoint_updates_auth_client(self):
        self.api.auth.set_region = MagicMock()
        self.api._update_region_from_endpoint("example.iot.ap-southeast-2.amazonaws.com")
        self.assertEqual(self.api.region, "ap-southeast-2")
        self.api.auth.set_region.assert_called_once_with("ap-southeast-2")

    def test_refresh_tokens_wraps_error(self):
        self.api.tokens = AuthTokens(
            access_token="a",
            id_token=self._build_token(),
            refresh_token="r",
            issued_at=datetime.utcnow(),
        )
        self.api.auth.refresh_token = MagicMock(side_effect=HydrosAuthError("boom"))
        with self.assertRaises(HydrosAuthError) as ctx:
            self.api.refresh_tokens()
        self.assertIn("Failed to refresh token", str(ctx.exception))

    def test_infer_iot_endpoint_from_nested_dict(self):
        nested = {"details": {"iotEndpoint": "endpoint.iot"}}
        self.assertEqual(self.api._infer_iot_endpoint(nested), "endpoint.iot")

    def test_connect_mqtt_requires_authentication(self):
        self.api.user_id = None
        with self.assertRaises(ValueError):
            self.api.connect_mqtt(thing_id="thing123")

    def test_connect_mqtt_requires_thing_id(self):
        self.api.user_id = "user123"
        with self.assertRaises(ValueError):
            self.api.connect_mqtt()

    def test_connect_mqtt_missing_identity_raises(self):
        self.api.tokens = AuthTokens(
            access_token="a",
            id_token=self._build_token(),
            refresh_token="r",
            issued_at=datetime.utcnow(),
        )
        self.api.user_id = "user123"
        with patch.object(self.api, "get_thing", return_value={"thingName": "example"}):
            with self.assertRaises(HydrosMQTTError):
                self.api.connect_mqtt(thing_id="thing123")

    def test_connect_mqtt_missing_endpoint_raises(self):
        self.api.tokens = AuthTokens(
            access_token="a",
            id_token=self._build_token(),
            refresh_token="r",
            issued_at=datetime.utcnow(),
        )
        self.api.user_id = "user123"
        thing = {"thingName": "example", "cognito_identity": "us-west-2:abc"}
        with patch.object(self.api, "get_thing", return_value=thing):
            with self.assertRaises(HydrosMQTTError):
                self.api.connect_mqtt(thing_id="thing123")

    def test_subscribe_requires_connection(self):
        self.api.user_id = "user123"
        self.api.mqtt_client = MagicMock()
        self.api.mqtt_client.connected = False
        with self.assertRaises(HydrosMQTTError):
            self.api.subscribe_thing_status("thing123", MagicMock())

    def test_subscribe_requires_user_id(self):
        self.api.user_id = None
        client = MagicMock()
        client.connected = True
        self.api.mqtt_client = client
        with self.assertRaises(HydrosMQTTError):
            self.api.subscribe_thing_status("thing123", MagicMock())

    def test_download_hydros_data_json_bad_payload_raises(self):
        with patch.object(self.api, "download_hydros_data", return_value=b"x\x9cBAD"):
            with self.assertRaises(HydrosAPIError):
                self.api.download_hydros_data_json("thing123")

    def test_ensure_authenticated_propagates_error(self):
        self.api.tokens = None
        with patch.object(self.api, "authenticate", side_effect=HydrosAuthError("fail")):
            with self.assertRaises(HydrosAuthError):
                self.api._ensure_authenticated()

    def test_get_headers_requires_tokens(self):
        self.api.tokens = None
        with patch.object(self.api, "authenticate", side_effect=HydrosAuthError("missing")):
            with self.assertRaises(HydrosAuthError):
                self.api._get_headers()

    def test_publish_command_requires_user_id(self):
        client = MagicMock()
        client.connected = True
        self.api.mqtt_client = client
        with self.assertRaises(HydrosMQTTError):
            self.api.publish_command("thing123", ("Mode", "Normal"))

    def test_publish_command_constructs_topic(self):
        self.api.user_id = "user123"
        client = MagicMock()
        client.connected = True
        self.api.mqtt_client = client
        self.api._ensure_mqtt_connected = MagicMock()

        payload = {"State": 1}
        self.api.publish_command(
            "thing123",
            ("Mode", "Normal"),
            payload,
            topic_prefix="F",
            method="PUT",
        )

        client.publish.assert_called_once()
        topic_arg, payload_arg = client.publish.call_args[0][:2]
        self.assertEqual(topic_arg, "Fuser123/thing123/req/PUT/Mode/Normal")
        self.assertEqual(payload_arg, payload)

    def test_set_output_state_uses_alias_and_prefix(self):
        self.api.user_id = "user123"
        client = MagicMock()
        client.connected = True
        self.api.mqtt_client = client
        self.api._ensure_mqtt_connected = MagicMock()

        self.api.set_output_state("thing123", "Heater1", "off")

        client.publish.assert_called_once()
        topic_arg, payload_arg = client.publish.call_args[0][:2]
        self.assertEqual(topic_arg, "buser123/thing123/req/PUT/Output/Heater1")
        self.assertEqual(payload_arg, {"State": 0, "Prefix": ""})

    def test_set_collective_mode_uses_literal_mode(self):
        self.api.user_id = "user123"
        client = MagicMock()
        client.connected = True
        self.api.mqtt_client = client
        self.api._ensure_mqtt_connected = MagicMock()

        self.api.set_collective_mode("thing123", "Feeding")

        client.publish.assert_called_once()
        topic_arg, payload_arg = client.publish.call_args[0][:2]
        self.assertEqual(topic_arg, "user123/thing123/req/PUT/Mode/Feeding")
        self.assertIsNone(payload_arg)

    def test_set_collective_mode_requires_mode(self):
        self.api.user_id = "user123"
        client = MagicMock()
        client.connected = True
        self.api.mqtt_client = client
        self.api._ensure_mqtt_connected = MagicMock()

        with self.assertRaises(ValueError):
            self.api.set_collective_mode("thing123", " ")

    def test_set_output_state_invalid_value_raises(self):
        self.api.user_id = "user123"
        client = MagicMock()
        client.connected = True
        self.api.mqtt_client = client
        self.api._ensure_mqtt_connected = MagicMock()

        with self.assertRaises(ValueError):
            self.api.set_output_state("thing123", "Heater1", "invalid")

    @patch("pyhydros.requests.get")
    def test_get_dosing_logs_parses_entries(self, mock_get):
        token = AuthTokens(
            access_token="a",
            id_token="id",
            refresh_token="r",
            issued_at=datetime.utcnow(),
        )
        self.api.tokens = token

        mock_response = MagicMock()
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = [
            {
                "time": 1700000000000,
                "value": 0,
                "valueDec": "1.25",
                "valueString": "Manual Dosed 1.25 ml",
            },
            {
                "time": "1700003600000",
                "value": "unused",
                "valueString": "Auto dose 2 ml",
            },
            {
                "time": 1700007200000,
                "value": 0,
                "valueDec": "0.000",
                "valueString": "Manual Dosed 1.1 ml",
            },
        ]
        mock_get.return_value = mock_response

        start_dt = datetime(2024, 1, 1, tzinfo=timezone.utc)
        end_dt = datetime(2024, 1, 2, tzinfo=timezone.utc)

        entries = self.api.get_dosing_logs(
            "Thing123",
            "Doser1",
            count=50,
            skip=10,
            start=start_dt,
            end=end_dt,
        )

        self.assertIsInstance(entries, list)
        self.assertEqual(len(entries), 3)
        self.assertTrue(all(isinstance(entry, HydrosDosingLogEntry) for entry in entries))

        params = mock_get.call_args.kwargs["params"]
        self.assertEqual(params["thingName"], "Thing123")
        self.assertEqual(params["name"], "Doser1")
        self.assertEqual(params["count"], 50)
        self.assertEqual(params["skip"], 10)
        self.assertEqual(
            params["start"],
            int(start_dt.timestamp() * 1000),
        )
        self.assertEqual(
            params["end"],
            int(end_dt.timestamp() * 1000),
        )

        first, second, third = entries
        self.assertAlmostEqual(first.quantity_ml or 0, 1.25, places=3)
        self.assertEqual(first.message, "Manual Dosed 1.25 ml")
        self.assertIsNotNone(first.timestamp)
        self.assertEqual(first.timestamp.tzinfo, timezone.utc)

        self.assertAlmostEqual(second.quantity_ml or 0, 2.0, places=3)
        self.assertEqual(second.message, "Auto dose 2 ml")
        self.assertEqual(second.timestamp.tzinfo, timezone.utc)

        self.assertAlmostEqual(third.quantity_ml or 0, 1.1, places=3)
        self.assertEqual(third.message, "Manual Dosed 1.1 ml")
        self.assertEqual(third.timestamp.tzinfo, timezone.utc)


if __name__ == "__main__":
    unittest.main()
