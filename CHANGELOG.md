# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.1] - 2026-04-07

### Fixed

- `change_mode()` now retries status verification until the timeout expires
  instead of failing on the first stale response. The controller often replies
  with the old mode before the switch completes, which previously caused a
  false "Mode verification failed" error.

## [0.4.0] - 2026-04-05

### Added

- `change_mode()` method for verified mode changes on Hydros controllers.
  Sends `PUT/Mode/<mode>`, waits for a `200` receipt acknowledgement, then
  requests a status refresh and confirms the controller actually switched
  to the requested mode.
- `_extract_ack_status()` static helper for parsing HTTP-like status codes
  from Hydros MQTT ack payloads.
- `_unsubscribe_filter()` on `MQTTClient` for clean removal of one-shot
  subscription handlers.
- `_decode_payload()` on `MQTTClient` to separate payload decoding from
  message dispatch.

### Changed

- **MQTT multi-dispatch**: `_handle_message` now delivers each incoming
  message to **all** matching subscription callbacks, not just the first
  match. 

## [0.3.0] - 2026-03-29

### Added

- Initial beta release of PyHydros.