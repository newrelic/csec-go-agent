# Changelog

## [v0.3.0] - 2023-07-24

- Fix for data race conditions observed by race detector.
- Update WS handler
   - Drop events when the websocket connection is not established.
   - Updated websocket reconnection time to 15 sec.
- New IAST informational messages in logs - start of URL and application trace analysis.
- Improve support for gRPC client.

## [v0.2.1] - 2023-06-12

- retract v0.2.0, protobuf cve fixed in v0.2.1

## [v0.2.0] - 2023-06-10

- Fix for removing temporary files in IAST
- Fix for ws abnormal closure issue
- Update handling for complete disabling of security agent.

## [v0.1.0] - 2023-05-30

- License update
- Improved Logging
- Fix for agent refresh
- Fix agent initialization in Windows

## [1.0.2-limited-preview] - 2023-05-18
- Fix for RXSS events.
- Fix for trace asynchronous applications
- Improved Logging

## [1.0.1-limited-preview] - 2023-04-28

### Initial IAST support

This module enables the instrumentation of golang applications for security analysis and runtime application protection.

### Compatibility matrix

- Go version 1.17+ is required.
- Linux and MacOS are supported.
- IAST Support for SYSTEM_COMMAND, FILE_OPERATION, APPLICATION_INTEGRITY, SQL_DB_COMMAND, NOSQL_DB_COMMAND, REFLECTED_XSS, SSRF, XPATH and LDAP event category.
- Support for net/http, gRPC frameworks
