"""
PyHydros: Python library for Cognito authentication and Hydros API access.

Implements AWS Cognito USER_SRP_AUTH authentication flow to obtain tokens
and provides authenticated access to the Hydros API at https://cv.hydros.link/user
Also supports real-time sensor data via AWS IoT MQTT.
"""

__version__ = "0.3.0"

import json
import logging
import requests
import os
import zlib
import base64
import re
import uuid
from urllib.parse import quote
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any, Callable, Sequence, Union, List
from dataclasses import dataclass
from dotenv import load_dotenv
import boto3
from botocore.exceptions import ClientError
from awscrt import auth as awscrt_auth, io as awscrt_io, mqtt as awscrt_mqtt
from awsiot import mqtt_connection_builder

# Enable to debug AWS IoT Device SDK logs
#import awscrt
#awscrt.io.init_logging(awscrt.io.LogLevel.Debug, 'stderr')


class HydrosError(Exception):
    """Base exception for PyHydros errors."""


class HydrosAuthError(HydrosError):
    """Raised when Cognito authentication fails."""


class HydrosAPIError(HydrosError):
    """Raised when Hydros REST API operations fail."""


class HydrosMQTTError(HydrosError):
    """Raised when MQTT operations fail."""

# Load environment variables from .env file

load_dotenv()

os.environ.setdefault("AWS_EC2_METADATA_DISABLED", "true")  # Avoid IMDS credential lookups outside AWS

logger = logging.getLogger(__name__)

# Safety limits
_MAX_DECOMPRESSED_BYTES = 10 * 1024 * 1024  # 10 MB
_AWS_REGION_RE = re.compile(r"^[a-z]{2}(-[a-z]+-\d+)$")
_ALLOWED_S3_HOSTS = (
    ".s3.amazonaws.com",
    ".s3-accelerate.amazonaws.com",
)
# Regional virtual-hosted S3 endpoints: <bucket>.s3.<region>.amazonaws.com
_S3_REGIONAL_HOST_RE = re.compile(
    r"^[a-z0-9.-]+\.s3\.[a-z]{2}-[a-z]+-\d+\.amazonaws\.com$"
)


def _safe_zlib_decompress(data: bytes, *, max_bytes: int = _MAX_DECOMPRESSED_BYTES) -> bytes:
    """Decompress zlib data with a size cap to prevent decompression bombs."""
    dobj = zlib.decompressobj()
    chunks: list[bytes] = []
    total = 0
    # Feed the data in one shot but limit output per call
    chunk = dobj.decompress(data, max_bytes + 1)
    total += len(chunk)
    if total > max_bytes:
        raise HydrosError(
            f"Decompressed payload exceeds {max_bytes} byte limit "
            f"({total}+ bytes) — possible decompression bomb"
        )
    chunks.append(chunk)
    # Drain any remaining buffered output
    while dobj.unconsumed_tail:
        chunk = dobj.decompress(dobj.unconsumed_tail, max_bytes - total + 1)
        total += len(chunk)
        if total > max_bytes:
            raise HydrosError(
                f"Decompressed payload exceeds {max_bytes} byte limit "
                f"({total}+ bytes) — possible decompression bomb"
            )
        chunks.append(chunk)
    return b"".join(chunks)


def _validate_s3_url(url: str) -> None:
    """Ensure a signed URL points to a known S3 host over HTTPS."""
    if not url or not url.startswith("https://"):
        raise HydrosAPIError(f"Signed URL must use HTTPS (got {url[:40]!r}…)")
    host = url.split("://", 1)[1].split("/", 1)[0].split("?", 1)[0].lower()
    if not (
        any(host.endswith(suffix) for suffix in _ALLOWED_S3_HOSTS)
        or _S3_REGIONAL_HOST_RE.match(host)
    ):
        raise HydrosAPIError(
            f"Signed URL host {host!r} is not a recognised S3 endpoint"
        )


def _validate_identifier(value: str, label: str = "identifier") -> str:
    """Validate and normalize ID-like values while blocking path traversal input."""
    if value is None:
        raise ValueError(f"Invalid {label}: {value!r}")

    normalized = str(value).strip()
    if not normalized:
        raise ValueError(f"Invalid {label}: {value!r}")

    if any(token in normalized for token in ("/", "\\", "..", "\x00")):
        raise ValueError(f"Invalid {label}: {value!r}")

    if any(ord(ch) < 32 for ch in normalized):
        raise ValueError(f"Invalid {label}: {value!r}")

    return normalized


def _redact_sensitive_fields(payload: Any) -> Any:
    """Recursively redact sensitive values in dict/list payloads for safe logging."""
    sensitive_exact_keys = {
        "generated_user_id",
        "certificate_arn",
        "thing_arn",
        "cognito_identity",
        "email",
    }

    sensitive_key_fragments = (
        "password",
        "secret",
        "token",
        "email",
        "identity",
        "user_id",
        "arn",
        "access_key",
        "session",
    )

    def _is_sensitive_key(key: str) -> bool:
        key_lower = key.lower()
        if key_lower in sensitive_exact_keys:
            return True
        return any(fragment in key_lower for fragment in sensitive_key_fragments)

    if isinstance(payload, dict):
        redacted: Dict[str, Any] = {}
        for key, value in payload.items():
            key_text = str(key)
            if _is_sensitive_key(key_text):
                redacted[key_text] = "<redacted>"
            else:
                redacted[key_text] = _redact_sensitive_fields(value)
        return redacted

    if isinstance(payload, list):
        return [_redact_sensitive_fields(item) for item in payload]

    return payload


@dataclass
class AuthTokens:
    """Represents AWS Cognito authentication tokens."""
    access_token: str
    id_token: str
    refresh_token: str
    token_type: str = "Bearer"
    expires_in: int = 3600
    issued_at: Optional[datetime] = None
    
    def is_expired(self) -> bool:
        """Check if access token is expired."""
        if not self.issued_at:
            return False
        expiry = self.issued_at + timedelta(seconds=self.expires_in)
        return datetime.utcnow() >= expiry


@dataclass
class HydrosDosingLogEntry:
    """Represents a dosing event returned by the Hydros logs API."""

    thing_name: str
    output_name: str
    timestamp: Optional[datetime]
    quantity_ml: Optional[float]
    message: Optional[str]
    raw: Dict[str, Any]

class CognitoSRPAuth:
    """Implements AWS Cognito SRP authentication using boto3."""
    
    def __init__(self, username: str, password: str, region: str = "us-west-2"):
        self.username = username
        self.password = password
        self.client_id = "3au5f4m5juu58qks62mcd89730"
        self.region = region
        self._init_client()

    def _init_client(self):
        """Initialise the Cognito IDP client for the current region."""
        self.idp_client = boto3.client('cognito-idp', region_name=self.region)

    def set_region(self, region: str):
        """Update the Cognito region and rebuild the boto3 client if required."""
        if region and region != self.region:
            self.region = region
            self._init_client()
    
    def authenticate(self) -> Dict[str, Any]:
        """
        Authenticate using SRP and return tokens.
        
        Returns:
            Dict with AuthenticationResult containing AccessToken, IdToken, RefreshToken
        """
        try:
            # Use boto3's built-in SRP authentication
            response = self.idp_client.initiate_auth(
                ClientId=self.client_id,
                AuthFlow='USER_PASSWORD_AUTH',
                AuthParameters={
                    'USERNAME': self.username,
                    'PASSWORD': self.password
                }
            )

            return response
        except ClientError as e:
            error_code = e.response['Error']['Code']
            error_message = e.response['Error']['Message']
            raise HydrosAuthError(
                f"Authentication failed ({error_code}): {error_message}"
            ) from e
    
    def refresh_token(self, refresh_token: str) -> Dict[str, Any]:
        """
        Refresh the access token.
        
        Args:
            refresh_token: The refresh token
            
        Returns:
            Dict with new tokens
        """
        try:
            response = self.idp_client.initiate_auth(
                ClientId=self.client_id,
                AuthFlow='REFRESH_TOKEN_AUTH',
                AuthParameters={
                    'REFRESH_TOKEN': refresh_token
                }
            )
            return response
        except ClientError as e:
            error_code = e.response['Error']['Code']
            error_message = e.response['Error']['Message']
            raise HydrosAuthError(
                f"Token refresh failed ({error_code}): {error_message}"
            ) from e


class MQTTClient:
    """AWS IoT MQTT client using the AWS IoT Device SDK over SigV4 WebSockets."""

    _event_loop_group: Optional[awscrt_io.EventLoopGroup] = None
    _host_resolver: Optional[awscrt_io.DefaultHostResolver] = None
    _client_bootstrap: Optional[awscrt_io.ClientBootstrap] = None

    def __init__(self, endpoint: str, region: str = "us-west-2"):
        """
        Initialize MQTT client for AWS IoT.

        Args:
            endpoint: AWS IoT endpoint (e.g., 'xxxxx-ats.iot.us-west-2.amazonaws.com')
            region: AWS region
        """
        self.endpoint = endpoint
        self.region = region
        self.connection: Optional[awscrt_mqtt.Connection] = None
        self.connected = False
        self.callbacks: Dict[str, Callable] = {}

    @classmethod
    def _ensure_bootstrap(cls):
        """Create shared event loop resources for the AWS IoT Device SDK."""
        if cls._event_loop_group is None:
            cls._event_loop_group = awscrt_io.EventLoopGroup(1)
            cls._host_resolver = awscrt_io.DefaultHostResolver(cls._event_loop_group)
            cls._client_bootstrap = awscrt_io.ClientBootstrap(
                cls._event_loop_group, cls._host_resolver
            )

    def _build_credentials_provider(self, session: boto3.Session) -> awscrt_auth.AwsCredentialsProvider:
        """Create a credentials provider from the temporary boto3 session."""
        credentials = session.get_credentials()
        if not credentials:
            raise HydrosMQTTError("No AWS credentials available for IoT connection")

        frozen = credentials.get_frozen_credentials()
        return awscrt_auth.AwsCredentialsProvider.new_static(
            access_key_id=frozen.access_key,
            secret_access_key=frozen.secret_key,
            session_token=frozen.token,
        )

    def connect(self, session: boto3.Session, client_id: str = "pyhydros"):
        """Connect to AWS IoT MQTT over WebSockets using SigV4 signing."""
        logger.info(f"Attempting to connect to {self.endpoint} via AWS IoT Device SDK...")

        self._ensure_bootstrap()
        credentials_provider = self._build_credentials_provider(session)

        self.connection = mqtt_connection_builder.websockets_with_default_aws_signing(
            endpoint=self.endpoint,
            client_bootstrap=self._client_bootstrap,
            region=self.region,
            credentials_provider=credentials_provider,
            client_id=client_id,
            clean_session=False,
            keep_alive_secs=60,
            on_connection_interrupted=self._on_connection_interrupted,
            on_connection_resumed=self._on_connection_resumed,
        )

        try:
            connect_future = self.connection.connect()
            connect_future.result(15)
            self.connected = True
            logger.info("✓ Connected to AWS IoT MQTT")
            self._subscribe_pending_topics()
        except Exception as exc:
            self.connected = False
            logger.error(f"✗ Failed to connect to MQTT: {exc}")
            raise HydrosMQTTError(
                f"Failed to connect to MQTT via AWS IoT SDK: {exc}"
            ) from exc

    def subscribe(self, topic: str, callback: Callable[[str, Dict], None]):
        """Subscribe to an MQTT topic with a JSON callback."""
        if not self.connection:
            logger.warning(f"⚠ No MQTT connection yet; queueing subscription to {topic}")

        self.callbacks[topic] = callback

        if self.connection and self.connected:
            self._subscribe_topic(topic)
        else:
            logger.warning("⚠ Not connected yet, will subscribe after connection")

    def _subscribe_topic(self, topic: str):
        """Subscribe to a topic on the active connection."""
        if not self.connection:
            return

        def _forward(*args, **kwargs):
            topic = None
            payload = None

            if len(args) >= 2:
                topic, payload = args[0], args[1]
            else:
                topic = kwargs.get('topic')
                payload = kwargs.get('payload')

            if topic is None or payload is None:
                logger.error("✗ MQTT callback missing topic or payload; skipping message")
                return

            self._handle_message(topic, payload)

        logger.info(f"Subscribing to: {topic}")
        try:
            subscribe_future, _ = self.connection.subscribe(
                topic=topic,
                qos=awscrt_mqtt.QoS.AT_LEAST_ONCE,
                callback=_forward,
            )
            subscribe_future.result(10)
        except Exception as exc:
            logger.error(f"✗ Failed to subscribe to {topic}: {exc}")
            raise HydrosMQTTError(f"Failed to subscribe to {topic}: {exc}") from exc

    def _handle_message(self, topic: str, payload: bytes):
        """Decode MQTT payload and dispatch to the registered callback."""
        logger.info(f"✓ Message received on {topic}")
        callback = self.callbacks.get(topic)
        matched_filter = None
        if not callback:
            for filter_topic, candidate in self.callbacks.items():
                if self._topic_matches(filter_topic, topic):
                    callback = candidate
                    matched_filter = filter_topic
                    break
            if callback and matched_filter and topic not in self.callbacks:
                # Cache resolved topic for faster lookups, without altering the original filter entry
                self.callbacks[topic] = callback
        if not callback:
            return

        if not payload:
            logger.warning("⚠ MQTT payload empty")
            callback(topic, {})
            return

        header_bytes: Optional[bytes] = None
        payload_bytes = payload

        # Some Hydros topics prefix the payload with a header and space before zlib data
        space_index = payload.find(b" ")
        if space_index != -1:
            candidate = payload[space_index + 1 :]
            if candidate[:2] in (b"x\x9c", b"x\x01"):
                header_bytes = payload[:space_index]
                payload_bytes = candidate

        # Attempt to decompress zlib-compressed data (size-limited)
        if payload_bytes[:2] in (b"x\x9c", b"x\x01"):
            try:
                payload_bytes = _safe_zlib_decompress(payload_bytes)
            except (zlib.error, HydrosError) as exc:
                logger.warning(f"⚠ Failed to decompress MQTT payload: {exc}")

        try:
            payload_text = payload_bytes.decode("utf-8")
        except UnicodeDecodeError:
            logger.warning("⚠ MQTT payload not valid UTF-8, forwarding raw bytes")
            callback(topic, payload_bytes)
            return

        payload_stripped = payload_text.strip()
        if not payload_stripped:
            logger.warning("⚠ MQTT payload empty after decoding")
            callback(topic, {})
            return

        try:
            data = json.loads(payload_stripped)
            if header_bytes and isinstance(data, dict):
                try:
                    header_text = header_bytes.decode("utf-8", errors="ignore").strip()
                    if header_text:
                        data.setdefault("_hydros_header", header_text)
                except Exception:
                    pass
            callback(topic, data)
        except json.JSONDecodeError as exc:
            logger.warning(f"⚠ MQTT payload not JSON: {exc}. Forwarding raw text to callback")
            if header_bytes:
                callback(topic, {"_hydros_header": header_bytes, "raw": payload_bytes})
            else:
                callback(topic, payload_text)

    def _subscribe_pending_topics(self):
        """Subscribe to any topics that were queued before the connection."""
        if not self.connection or not self.callbacks:
            return
        for topic in self.callbacks.keys():
            self._subscribe_topic(topic)

    @staticmethod
    def _topic_matches(topic_filter: str, topic: str) -> bool:
        """Check if an MQTT topic matches a subscription filter with wildcards."""
        filter_levels = topic_filter.split('/')
        topic_levels = topic.split('/')

        for index, level in enumerate(filter_levels):
            if level == '#':
                return True
            if index >= len(topic_levels):
                return False
            if level == '+':
                continue
            if level != topic_levels[index]:
                return False

        return len(topic_levels) == len(filter_levels)

    def _on_connection_interrupted(self, connection, error, **kwargs):
        """Handle unexpected interruptions."""
        self.connected = False
        logger.error(f"✗ MQTT connection interrupted: {error}")

    def _on_connection_resumed(self, connection, return_code, session_present, **kwargs):
        """Attempt to resubscribe when the connection is resumed."""
        if return_code == awscrt_mqtt.ConnectReturnCode.ACCEPTED:
            self.connected = True
            logger.info("✓ MQTT connection resumed")
            if not session_present:
                self._subscribe_pending_topics()
        else:
            logger.error(f"✗ MQTT connection resumed with code: {return_code}")

    def disconnect(self):
        """Disconnect cleanly from AWS IoT."""
        if not self.connection:
            return
        try:
            self.connection.disconnect().result(5)
        finally:
            self.connected = False
            self.connection = None

    def publish(self, topic: str, payload: Optional[Any] = None, qos: awscrt_mqtt.QoS = awscrt_mqtt.QoS.AT_LEAST_ONCE, retain: bool = False):
        """Publish a message to an MQTT topic."""
        if not self.connection or not self.connected:
            raise HydrosMQTTError("MQTT publish attempted without an active connection")

        if payload is None:
            payload_bytes = b""
        elif isinstance(payload, bytes):
            payload_bytes = payload
        elif isinstance(payload, str):
            payload_bytes = payload.encode("utf-8")
        else:
            payload_bytes = json.dumps(payload).encode("utf-8")

        try:
            publish_future, _ = self.connection.publish(
                topic=topic,
                payload=payload_bytes,
                qos=qos,
                retain=retain,
            )
            publish_future.result(10)
        except Exception as exc:
            logger.error(f"✗ Failed to publish to {topic}: {exc}")
            raise HydrosMQTTError(f"Failed to publish to {topic}: {exc}") from exc


class HydrosAPI:
    """Client for Hydros API with Cognito authentication."""
    
    def __init__(self, username: Optional[str] = None, password: Optional[str] = None, region: Optional[str] = None):
        """
        Initialize HydrosAPI client.
        
        Args:
            username: Cognito username (email). If not provided, loads from HYDROS_USERNAME env var.
            password: Cognito password. If not provided, loads from HYDROS_PASSWORD env var.
        
        Raises:
            ValueError: If credentials are not provided and not found in environment.
        """
        # Use provided credentials or load from environment variables
        self.username = username or os.getenv("HYDROS_USERNAME")
        self.password = password or os.getenv("HYDROS_PASSWORD")
        self.region = region or os.getenv("HYDROS_REGION") or "us-west-2"
        
        if not self.username or not self.password:
            raise ValueError(
                "Credentials required. Provide as arguments or set HYDROS_USERNAME "
                "and HYDROS_PASSWORD environment variables in .env file"
            )
        
        self.tokens: Optional[AuthTokens] = None
        self.api_url = "https://cv.hydros.link"
        self.auth = CognitoSRPAuth(self.username, self.password, region=self.region)
        self.user_id: Optional[str] = None  # Will be populated after authentication
        self.user_profile: Optional[Dict[str, Any]] = None
        self.mqtt_client: Optional[MQTTClient] = None
    
    def authenticate(self) -> AuthTokens:
        """
        Authenticate with Cognito and obtain tokens.
        
        Returns:
            AuthTokens: Contains access_token, id_token, and refresh_token
        """
        # Use SRP authentication to get tokens
        auth_response = self.auth.authenticate()
        auth_result = auth_response.get("AuthenticationResult", {})
        
        id_token = auth_result["IdToken"]
        
        self.tokens = AuthTokens(
            access_token=auth_result["AccessToken"],
            id_token=id_token,
            refresh_token=auth_result["RefreshToken"],
            expires_in=auth_result.get("ExpiresIn", 3600),
            issued_at=datetime.utcnow()
        )
        self._update_region_from_token(id_token)
        
        # Extract user_id from API response (generated_user_id)
        try:
            user_info = self.get_user()
            self.user_id = user_info.get('generated_user_id')
            if self.user_id:
                logger.info(f"✓ User authenticated (ID: {self.user_id})")
        except Exception as e:
            logger.warning(f"Warning: Could not retrieve user info: {str(e)}")
        
        return self.tokens
    
    def _ensure_authenticated(self):
        """Ensure we have valid tokens, refresh if needed."""
        if not self.tokens:
            self.authenticate()
        elif self.tokens.is_expired():
            self.refresh_tokens()
    
    @staticmethod
    def _decode_jwt_payload(token: str) -> Dict[str, Any]:
        """Decode the payload section of a JWT without verification."""
        parts = token.split('.')
        if len(parts) < 2:
            raise ValueError("Token does not have a payload segment")
        payload = parts[1]
        padding = -len(payload) % 4
        if padding:
            payload += '=' * padding
        decoded = base64.urlsafe_b64decode(payload)
        return json.loads(decoded)

    def _update_region_from_token(self, id_token: str):
        """Derive AWS region from the Cognito ID token issuer."""
        try:
            token_data = self._decode_jwt_payload(id_token)
            iss = token_data.get('iss', '')
            # Only trust issuers that match the Cognito URL pattern
            if not iss or not re.match(
                r"^https://cognito-idp\.[a-z]{2}(-[a-z]+-\d+)\.amazonaws\.com/",
                iss,
            ):
                logger.debug("JWT issuer %r does not match Cognito pattern; skipping region update", iss)
                return
            pool_fragment = iss.rstrip('/').split('/')[-1] if iss else None
            region_candidate = None
            if pool_fragment and '_' in pool_fragment:
                region_candidate = pool_fragment.split('_', 1)[0]
            elif pool_fragment and pool_fragment.startswith('aws-'):
                region_candidate = pool_fragment
            if region_candidate and not _AWS_REGION_RE.match(region_candidate):
                logger.warning("Derived region %r does not look valid; ignoring", region_candidate)
                return
            if region_candidate:
                self._apply_region_update(region_candidate, "token issuer")
        except Exception:
            # Silent failure keeps existing region if parsing fails
            pass

    def _update_region_from_endpoint(self, endpoint: str):
        """Derive AWS region from an IoT endpoint hostname."""
        if not endpoint:
            return

        host = endpoint.strip()
        if host.startswith("https://") or host.startswith("http://"):
            host = host.split("://", 1)[1]
        host = host.split("/", 1)[0]

        parts = host.split('.')
        try:
            idx = parts.index("iot")
        except ValueError:
            return

        if idx + 1 >= len(parts):
            return

        region_candidate = parts[idx + 1]
        if region_candidate and _AWS_REGION_RE.match(region_candidate):
            self._apply_region_update(region_candidate, "IoT endpoint")

    def _apply_region_update(self, region_candidate: str, source: str) -> None:
        if not region_candidate or region_candidate == self.region:
            return
        logger.info(f"Updating AWS region to {region_candidate} derived from {source}")
        self.region = region_candidate
        self.auth.set_region(region_candidate)

    def refresh_tokens(self):
        """Refresh the access token using the refresh token."""
        if not self.tokens or not self.tokens.refresh_token:
            raise ValueError("No refresh token available")
        
        try:
            refresh_response = self.auth.refresh_token(self.tokens.refresh_token)
            auth_result = refresh_response.get("AuthenticationResult", {})
            
            self.tokens = AuthTokens(
                access_token=auth_result["AccessToken"],
                id_token=auth_result.get("IdToken", self.tokens.id_token),
                refresh_token=auth_result.get("RefreshToken", self.tokens.refresh_token),
                expires_in=auth_result.get("ExpiresIn", 3600),
                issued_at=datetime.utcnow()
            )
            if auth_result.get("IdToken"):
                self._update_region_from_token(self.tokens.id_token)
        except HydrosAuthError as e:
            raise HydrosAuthError(f"Failed to refresh token: {str(e)}") from e
        except Exception as e:
            raise HydrosAuthError(f"Failed to refresh token: {str(e)}") from e
    
    def _get_headers(self) -> Dict[str, str]:
        """Get headers with authorization."""
        self._ensure_authenticated()
        # Use ID token (not access token) without Bearer prefix
        return {
            "Authorization": self.tokens.id_token,
            "Content-Type": "application/json"
        }

    def _infer_iot_endpoint(self, *sources: Optional[Dict[str, Any]]) -> Optional[str]:
        """Attempt to extract an AWS IoT endpoint from API payloads."""
        keys = (
            "iotEndpoint",
            "iot_endpoint",
            "mqttEndpoint",
            "mqtt_endpoint",
            "awsIotEndpoint",
            "aws_iot_endpoint",
            "iotEndpointAddress",
        )
        for source in sources:
            if not source or not isinstance(source, dict):
                continue
            for key in keys:
                value = source.get(key)
                if value:
                    return value
            for nested in source.values():
                if isinstance(nested, dict):
                    for key in keys:
                        value = nested.get(key)
                        if value:
                            return value
        return None
    
    def get_user(self) -> Dict[str, Any]:
        """
        Get user information from the API.
        
        Returns:
            Dict containing user information
        """
        response = requests.get(
            f"{self.api_url}/user",
            headers=self._get_headers()
        )
        response.raise_for_status()
        data = response.json()
        self.user_profile = data
        return data
    
    def get_thing(self, thing_id: str) -> Dict[str, Any]:
        """
        Get sensor/thing information by ID.
        
        Args:
            thing_id: The ID of the sensor/thing 
        
        Returns:
            Dict containing sensor/thing data
        """
        thing_id = _validate_identifier(thing_id, "thing_id")
        encoded_thing_id = quote(thing_id, safe="")
        response = requests.get(
            f"{self.api_url}/thing/{encoded_thing_id}",
            headers=self._get_headers()
        )
        response.raise_for_status()
        return response.json()
    
    def update_thing(self, thing_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Update sensor/thing configuration.
        
        Args:
            thing_id: The ID of the sensor/thing
            data: Configuration data to update
        
        Returns:
            Updated thing data
        """
        thing_id = _validate_identifier(thing_id, "thing_id")
        encoded_thing_id = quote(thing_id, safe="")
        response = requests.put(
            f"{self.api_url}/thing/{encoded_thing_id}",
            json=data,
            headers=self._get_headers()
        )
        response.raise_for_status()
        return response.json()
    
    def get_signed_url(self, hydros_id: str, method: str = "GET") -> str:
        """Get a signed S3 URL for accessing Hydros configuration data."""
        hydros_id = _validate_identifier(hydros_id, "hydros_id")
        response = requests.post(
            f"{self.api_url}/signed_url",
            json={"method": method, "key": hydros_id},
            headers=self._get_headers()
        )
        response.raise_for_status()
        # Response is just the URL as a string or wrapped in JSON
        result = response.json() if response.headers.get('content-type') == 'application/json' else response.text
        # If it's a dict, extract the URL, otherwise return as-is
        if isinstance(result, dict):
            return result.get('url', result)
        return result
    
    def download_hydros_data(self, hydros_id: str) -> bytes:
        """Download Hydros configuration from S3 using a signed URL."""
        signed_url = self.get_signed_url(hydros_id)
        _validate_s3_url(signed_url)
        
        # Download from S3 (no auth header needed for signed URL)
        response = requests.get(signed_url)
        response.raise_for_status()
        return response.content
    
    def download_hydros_data_json(self, hydros_id: str) -> Dict[str, Any]:
        """Download Hydros configuration from S3, decompress, and parse as JSON."""
        data = self.download_hydros_data(hydros_id)
        
        # Check if data is zlib compressed (starts with 0x78 0x9c or 0x78 0x01)
        if data[:2] == b'x\x9c' or data[:2] == b'x\x01':
            try:
                data = _safe_zlib_decompress(data)
            except (zlib.error, HydrosError) as e:
                raise HydrosAPIError(f"Failed to decompress Hydros data: {str(e)}") from e
        
        return json.loads(data)

    def get_dosing_logs(
        self,
        thing_name: str,
        output_name: str,
        *,
        count: int = 100,
        skip: int = 0,
        start: Optional[Union[int, float, str, datetime]] = None,
        end: Optional[Union[int, float, str, datetime]] = None,
    ) -> List[HydrosDosingLogEntry]:
        """
        Retrieve dosing log entries for a specific output.

        Args:
            thing_name: Hydros thing name housing the doser.
            output_name: Output name (for example "Doser1").
            count: Maximum number of records to return.
            skip: Number of records to skip (for pagination).
            start: Optional start time (datetime or epoch millis).
            end: Optional end time (datetime or epoch millis).

        Returns:
            A list of HydrosDosingLogEntry instances ordered newest-first.
        """

        params: Dict[str, Union[str, int]] = {
            "thingName": thing_name,
            "name": output_name,
            "count": count,
            "skip": skip,
        }

        start_ms = self._coerce_epoch_millis(start)
        end_ms = self._coerce_epoch_millis(end)
        if start_ms is not None:
            params["start"] = start_ms
        if end_ms is not None:
            params["end"] = end_ms

        response = requests.get(
            f"{self.api_url}/logs",
            headers=self._get_headers(),
            params=params,
        )
        response.raise_for_status()
        payload = response.json()
        if not isinstance(payload, list):
            raise HydrosAPIError("Unexpected response payload when fetching logs")

        entries: List[HydrosDosingLogEntry] = []
        for record in payload:
            if not isinstance(record, dict):
                continue
            timestamp = self._coerce_timestamp(record.get("time"))
            quantity = self._extract_dosing_quantity(record)
            message_raw = record.get("valueString")
            message = message_raw if isinstance(message_raw, str) else None
            entries.append(
                HydrosDosingLogEntry(
                    thing_name=thing_name,
                    output_name=output_name,
                    timestamp=timestamp,
                    quantity_ml=quantity,
                    message=message,
                    raw=record,
                )
            )
        return entries

    @staticmethod
    def _coerce_timestamp(value: Any) -> Optional[datetime]:
        if isinstance(value, (int, float)):
            try:
                return datetime.fromtimestamp(value / 1000.0, tz=timezone.utc)
            except (OverflowError, OSError, ValueError):
                return None
        if isinstance(value, str):
            try:
                numeric = float(value.strip())
            except (ValueError, AttributeError):
                return None
            return HydrosAPI._coerce_timestamp(numeric)
        return None

    @classmethod
    def _extract_dosing_quantity(cls, record: Dict[str, Any]) -> Optional[float]:
        value_string = record.get("valueString")
        if isinstance(value_string, str):
            match = cls._DOSE_VALUE_PATTERN.search(value_string)
            if match:
                try:
                    return float(match.group(1))
                except ValueError:
                    return None

        for key in ("valueDec", "value"):
            raw_value = record.get(key)
            if raw_value is None:
                continue
            try:
                numeric = float(raw_value)
            except (TypeError, ValueError):
                try:
                    numeric = float(str(raw_value).strip())
                except (ValueError, TypeError):
                    continue
            return numeric
        return None

    @staticmethod
    def _coerce_epoch_millis(value: Optional[Union[int, float, str, datetime]]) -> Optional[int]:
        if value is None:
            return None
        if isinstance(value, datetime):
            if value.tzinfo is None:
                value = value.replace(tzinfo=timezone.utc)
            else:
                value = value.astimezone(timezone.utc)
            return int(value.timestamp() * 1000)
        if isinstance(value, (int, float)):
            return int(value)
        if isinstance(value, str):
            stripped = value.strip()
            if not stripped:
                return None
            try:
                return int(float(stripped))
            except ValueError as exc:
                raise TypeError(f"Could not interpret value '{value}' as epoch millis") from exc
        raise TypeError(f"Unsupported timestamp type: {type(value)!r}")
    
    ALERT_LEVEL_LABELS: Dict[int, str] = {
        0: "None",
        1: "Yellow",
        4: "Orange",
        8: "Red",
    }

    PROBE_MODE_LABELS: Dict[int, str] = {
        0: "Unused",
        1: "PH",
        2: "ORP (mV)",
        3: "Alk (dKH)",
    }

    TRIPLE_LEVEL_LABELS: Dict[int, str] = {
        0: "Dry",
        1: "Wet",
        2: "Overflow",
    }

    _OUTPUT_STATE_ALIASES: Dict[str, int] = {
        "off": 0,
        "on": 1,
        "auto": -1,
    }

    _OUTPUT_STATE_TOPIC_PREFIXES: Dict[int, str] = {
        0: "b",
        -1: "H",
    }

    _DOSE_VALUE_PATTERN = re.compile(r"([0-9]+(?:\.[0-9]+)?)\s*ml", re.IGNORECASE)

    def connect_mqtt(self, thing_id: Optional[str] = None, client_id: str = "pyhydros") -> MQTTClient:
        """
        Connect to AWS IoT MQTT for real-time sensor data.
        
        Args:
            mqtt_endpoint: Optional AWS IoT endpoint. If omitted, the method attempts to
                extract an endpoint from Hydros API responses.
            thing_id: Thing ID to get Cognito Identity Pool ID from
            client_id: MQTT client ID
        
        Returns:
            Connected MQTTClient instance
        """
        if client_id == "pyhydros":
            client_id = f"{client_id}-{uuid.uuid4().hex}"

        if not self.user_id:
            raise ValueError("Not authenticated. Call authenticate() first.")
        
        if not thing_id:
            raise ValueError("thing_id is required to get Cognito Identity Pool ID")
        
        try:
            # Get thing details
            logger.info(f"Getting thing details...")
            thing_details = self.get_thing(thing_id)
            
            # If this is a child sensor, get the parent thing
            parent_thing_id = thing_details.get('parent')
            if parent_thing_id:
                logger.info(f"This is a child sensor, getting parent thing: {parent_thing_id}")
                thing_details = self.get_thing(parent_thing_id)
            
            # Get cognito_identity (it's already an IdentityId, not a pool ID)
            identity_id = thing_details.get('cognito_identity')
            if not identity_id:
                raise HydrosMQTTError("No cognito_identity found in thing details")
            
            logger.info(f"✓ Got Identity ID: {identity_id}")

            resolved_endpoint = self._infer_iot_endpoint(thing_details, self.user_profile)
            if not resolved_endpoint:
                raise HydrosMQTTError(
                    "MQTT endpoint not provided and not found in API response. "
                    "Pass mqtt_endpoint explicitly or ensure API includes iotEndpoint."
                )
            
            logger.info(f"Using IoT endpoint from API: {resolved_endpoint}")
            self._update_region_from_endpoint(resolved_endpoint)

            # Initialize AWS IoT Device SDK client
            self.mqtt_client = MQTTClient(resolved_endpoint, region=self.region)
            
            # Extract user pool ID from ID token
            # Token has issuer like: https://cognito-idp.us-west-2.amazonaws.com/us-west-2_XXXXXX
            try:
                token_data = self._decode_jwt_payload(self.tokens.id_token)
                iss = token_data.get('iss', '')
                user_pool_id = iss.split('/')[-1] if '/' in iss else None
                
                if not user_pool_id:
                    raise HydrosMQTTError(
                        f"Could not extract user_pool_id from token issuer: {iss}"
                    )
                
                logger.info(f"✓ Got User Pool ID: {user_pool_id}")
            except HydrosMQTTError:
                raise
            except Exception as e:
                raise HydrosMQTTError(
                    f"Failed to extract user pool ID from token: {str(e)}"
                ) from e
            
            # Get temporary AWS credentials from Cognito Identity
            cognito_identity_client = boto3.client('cognito-identity', region_name=self.region)
            
            # Get temporary credentials using the identity ID we got from thing details
            logger.info(f"Getting temporary AWS credentials...")
            creds_response = cognito_identity_client.get_credentials_for_identity(
                IdentityId=identity_id,
                Logins={
                    f'cognito-idp.{self.region}.amazonaws.com/{user_pool_id}': self.tokens.id_token
                }
            )
            
            temp_creds = creds_response['Credentials']
            logger.info(f"✓ Got temporary credentials (AccessKeyId: {temp_creds['AccessKeyId'][:10]}...)")
            
            # Create session with temporary credentials
            session = boto3.Session(
                aws_access_key_id=temp_creds['AccessKeyId'],
                aws_secret_access_key=temp_creds['SecretKey'],
                aws_session_token=temp_creds['SessionToken'],
                region_name=self.region
            )
            
            self.mqtt_client.connect(session, client_id=client_id)
            
        except Exception as e:
            logger.error(f"✗ Failed to get credentials: {str(e)}", exc_info=True)
            raise HydrosMQTTError(f"Failed to connect MQTT: {str(e)}") from e
        
        return self.mqtt_client
    
    def list_things(self) -> list:
        """
        Get a quick list of all sensor/thing IDs.
        
        Returns:
            List of thing IDs (sensor identifiers)
        """
        user_info = self.get_user()
        things = user_info.get('things', [])
        return [thing.get('thingName', thing.get('id')) for thing in things]
    
    def subscribe_thing_status(self, thing_id: str, callback: Callable[[str, Dict], None]):
        """
        Subscribe to real-time status updates for a sensor/thing.
        
        Args:
            thing_id: The thing ID
            callback: Function to call when status update received (receives topic, payload_dict)
        """
        if not self.mqtt_client or not self.mqtt_client.connected:
            raise HydrosMQTTError("MQTT not connected. Call connect_mqtt() first.")

        if not self.user_id:
            raise HydrosMQTTError("User ID not available. Call authenticate() first.")
        
        # Subscribe to thing status topic
        response_topic = f"{self.user_id}/{thing_id}/rsp/#"
        request_topic = f"{self.user_id}/{thing_id}/req/LISTEN/statusc"

        logger.info(f"Subscribing to: {response_topic}")
        self.mqtt_client.subscribe(response_topic, callback)

        # Send request to start streaming status updates (empty payload matches web client)
        try:
            self.mqtt_client.publish(request_topic, payload=b"", qos=awscrt_mqtt.QoS.AT_LEAST_ONCE)
            logger.info(f"Requested status updates on {request_topic}")
        except Exception as exc:
            logger.warning(f"⚠ Failed to request status updates: {exc}")

    def _ensure_mqtt_connected(self, thing_id: str, *, client_id: str = "pyhydros") -> None:
        """Ensure an MQTT session is active before publishing commands."""
        if self.mqtt_client and getattr(self.mqtt_client, "connected", False):
            return
        self.connect_mqtt(thing_id=thing_id, client_id=client_id)

    def publish_command(
        self,
        thing_id: str,
        command_path: Union[Sequence[str], str],
        payload: Optional[Any] = None,
        *,
        method: str = "PUT",
        topic_prefix: Optional[str] = None,
        client_id: str = "pyhydros",
        qos: awscrt_mqtt.QoS = awscrt_mqtt.QoS.AT_LEAST_ONCE,
        retain: bool = False,
    ) -> None:
        """Publish a Hydros MQTT command to the specified thing."""
        if not self.user_id:
            raise HydrosMQTTError("User ID not available. Call authenticate() first.")

        if not thing_id:
            raise ValueError("thing_id is required")

        if isinstance(command_path, str):
            command_parts = [command_path]
        else:
            command_parts = list(command_path)

        sanitized_parts = [part.strip("/") for part in command_parts if part]
        if not sanitized_parts:
            raise ValueError("command_path must contain at least one segment")

        method_token = (method or "").strip().upper() or "PUT"

        topic_prefix_value = topic_prefix or ""
        topic = f"{topic_prefix_value}{self.user_id}/{thing_id}/req/{method_token}/" + "/".join(sanitized_parts)

        self._ensure_mqtt_connected(thing_id, client_id=client_id)
        if not self.mqtt_client or not getattr(self.mqtt_client, "connected", False):
            raise HydrosMQTTError("MQTT client is not connected")

        self.mqtt_client.publish(topic, payload, qos=qos, retain=retain)

    def set_output_state(
        self,
        thing_id: str,
        output_name: str,
        state: Union[int, str], # off, on, auto
        *,
        topic_prefix: Optional[str] = None,
        payload_prefix: str = "",
        client_id: str = "pyhydros",
        qos: awscrt_mqtt.QoS = awscrt_mqtt.QoS.AT_LEAST_ONCE,
    ) -> None:
        """Change the state of a named output via MQTT."""
        numeric_state = self._coerce_output_state(state)
        payload = {"State": numeric_state, "Prefix": payload_prefix}
        topic_prefix_value = topic_prefix
        if topic_prefix_value is None:
            topic_prefix_value = self._OUTPUT_STATE_TOPIC_PREFIXES.get(numeric_state, "")

        self.publish_command(
            thing_id,
            ("Output", output_name),
            payload,
            topic_prefix=topic_prefix_value,
            client_id=client_id,
            qos=qos,
        )

    def set_collective_mode(
        self,
        thing_id: str,
        mode: str, # User defined; Hydros defaults are: Feeding, Normal and Water Change
        *,
        topic_prefix: Optional[str] = None,
        payload: Optional[Dict[str, Any]] = None,
        client_id: str = "pyhydros",
        qos: awscrt_mqtt.QoS = awscrt_mqtt.QoS.AT_LEAST_ONCE,
    ) -> None:
        """Update the collective operating mode via MQTT using a literal mode string."""
        mode_token = str(mode or "").strip()
        if not mode_token:
            raise ValueError("mode must be provided")

        topic_prefix_value = topic_prefix or ""

        self.publish_command(
            thing_id,
            ("Mode", mode_token),
            payload,
            topic_prefix=topic_prefix_value,
            client_id=client_id,
            qos=qos,
        )

    def _coerce_output_state(self, state: Union[int, str]) -> int:
        """Normalize textual output states to their numeric representation."""
        if isinstance(state, int):
            return state

        lookup_key = str(state).strip().lower()
        if lookup_key not in self._OUTPUT_STATE_ALIASES:
            raise ValueError(
                "Unsupported output state. Use numeric values or one of: "
                + ", ".join(sorted(self._OUTPUT_STATE_ALIASES))
            )
        return self._OUTPUT_STATE_ALIASES[lookup_key]


# Example usage
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="[%(levelname)s] [%(asctime)s] %(message)s")

    import time
    
    # Initialize the client
    client = HydrosAPI()
    
    # Authenticate
    logger.info("=" * 60)
    logger.info("HYDROS API CLIENT - EXAMPLE")
    logger.info("=" * 60)
    logger.info("\n1. Authenticating...")
    
    tokens = client.authenticate()
    logger.info(f"✓ Authenticated successfully")
    logger.info(f"  User ID: {client.user_id}\n")
    
    # Get user info
    logger.info("2. Getting user information...")
    user_info = client.get_user()
    things = user_info.get('things', [])
    logger.info(f"✓ Found {len(things)} hydros\n")
    for thing in things:
        thing_id = thing.get('thingName', thing.get('id', 'Unknown'))
        logger.info(f"  - Hydros: {_redact_sensitive_fields(thing)}")

    if not things:
        logger.info("No sensors found")
        exit(1)
    
    collective_thing = None

    # Choose the device or collective 
    for thing in things:
        if thing.get('thingType') == 'Collective':
            collective_thing = thing
            break

    if not collective_thing:
        collective_thing = things[0]    

    thing_id = collective_thing.get('thingName', collective_thing.get('id', 'Unknown'))
    logger.info(f"3. Using thing: {thing_id}\n")
    
    # Show hydros configuration
    logger.info("4. Hydros Configuration:")
    logger.info("-" * 60)
    sensor_metadata = client.get_thing(thing_id)
    logger.info(f"  Friendly Name: {sensor_metadata.get('friendlyName')}")
    logger.info(f"  Status: {'Connected' if sensor_metadata.get('connectionStatus') == 1 else 'Disconnected'}")
    logger.info(f"  Last Update: {sensor_metadata.get('lastStatusDate', 'Unknown')}")
    
    # Download sensor data
    logger.info("\n5. Downloading Configuration Data from S3...")
    logger.info("-" * 60)
    try:
        sensor_data = client.download_hydros_data_json(thing_id)
        if sensor_data:
            logger.info(sensor_data)
            
    except Exception as e:
        logger.error(f"✗ Could not fetch S3 data: {e}")

    # Example get doser logs
    # local_now = datetime.now().astimezone()
    # start_of_day = local_now.replace(hour=0, minute=0, second=0, microsecond=0)
    # end_of_day = start_of_day + timedelta(days=1)
    # logs = client.get_dosing_logs(
    #     thing_id,
    #     "<doser_name>",
    #     count=500,
    #     start=start_of_day,
    #     end=end_of_day,
    # )
    # total_ml = 0.0
    # for log in logs:
    #     if log.quantity_ml is not None:
    #         total_ml += float(log.quantity_ml)
    #     logger.info(
    #         f"Dosing Log - Time: {log.timestamp}, Quantity: {log.quantity_ml} ml, Message: {log.message}"
    #     )
    # logger.info(f"Total dosed today: {round(total_ml, 3)} ml")
    
    # Connect to MQTT and subscribe to sensor status
    logger.info("\n6. Attempting Real-Time Monitoring via MQTT...")
    logger.info("-" * 60)
    
    try:
        client.connect_mqtt(thing_id=thing_id)
        
        # Define callback to print received messages
        def on_message_received(topic, payload):
            timestamp = datetime.now().strftime('%H:%M:%S')
            logger.info(f"\n[{timestamp}] Message received on {topic}:")
            if isinstance(payload, dict):
                logger.debug(json.dumps(payload, indent=2))
            else:
                logger.debug(payload)
        
        # Subscribe to sensor status
        client.subscribe_thing_status(thing_id, on_message_received)
        
        # Listen for messages for 600 seconds
        logger.info("✓ Subscribed to sensor topic")
        logger.info("\nListening for MQTT messages (5 seconds)...")
        logger.info("=" * 60)
        
        for i in range(5):
            time.sleep(1)
            if (i + 1) % 10 == 0:
                logger.info(f"[{i + 1}s] Still listening...")
        
        logger.info("\n✓ Done listening")
        
    except Exception as e:
        logger.warning(f"⚠ MQTT not available: {str(e)}")
    