# Changelog
## [1.0.3-limited-preview] - 2023-05-23

- License update
- Improved Logging

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
