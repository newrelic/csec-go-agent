# Changelog

## [v1.6.0] - 2024-12-16

### Features:
* Added Support for Graphql framework graphql-go/graphql.
* Added support for IAST CI/CD and Scan Controllers.
 Configuration via yaml:
   ```yaml
   # This configuration allows users to specify a unique test identifier when running IAST Scan with CI/CD
   iast_test_identifier: 'run-id'

   scan_controllers:
      # This configuration allows users to the number of application instances for a specific entity where IAST analysis is performed.
      scan_instance_count:  0 # Values are 1 or 0, 0 signifies run on all application instances
  ```

### Fixes
* Fix query parameter encoding for replaying fuzz requests.

## [v1.5.0] - 2024-10-29
### Features:
* Json Version bump to 1.2.9.
* Add IAST Scan start time and Traffic Start Time in Health Check
* Add feature to allow IAST Scan Scheduling.
* Add feature to ignore IAST Scan of certain APIs, categories, or parameters.
* Add feature to rate limit the IAST replay requests.
* Add trace.id in event json.
* Add request uri in application runtime error event.

### Fixes
* Fix for wrong user file name for RXSS event in windows environment.

## [v1.4.0] - 2024-08-27
### Features:
* Added new key identifiers to all event JSONs.
* Introduced detailed IAST scan metric reporting via HealthCheck for better insights.
* Added support for Secure Cookie event reporting to provide detailed vulnerability information.
* Added support for application/xml and text/xml content-types for RXSS vulnerability detection.
* Implemented a new mechanism to uniquely generate low severity events based on API ID, with a 30-minute time interval

### Changes:
* Update IAST Header Parsing Minimum Expected Length Set to 8.
* Updated API ID generation to utilize both stacktrace and route information.
* Performed comprehensive code refactoring and cleanup for improved system efficiency and maintainability.
* Json Version bump to 1.2.5

### Deprecations:
* Status File Used for Debugging: This feature has been deprecated. All debugging capabilities have been moved to either Init Logging or Error Inbox and will be removed in a future agent release

## [v1.3.0] - 2024-06-24
### Features
* Added functionality to report panics in user code.
* Added support to report 5xx status code.
* Added support to detect gRPC API endpoint.
* Added support for MongoDB latest version v1.15.0
* Added feature to detect route of an incoming request for all supported frameworks.
* Added support to detect server web directory
* Added generic code to run agent on os like OpenBSD, FreeBSD
### Miscellaneous chores
* Fixed for incorrect system memory reporting on darwin
* Fixed for duplicate URL mapping reporting issue
* No Longer Sending Fuzz Fail Events
* Json Version bump to 1.2.3

## [v1.2.0] - 2024-04-12
### Features
* IAST replay header decryption due to Security Findings.
* Json Version bump to 1.2.0
### Miscellaneous chores
* Prepended the vulnerability case type with apiId.
* Updated time interval for IAST pull request.
* Bumped golang.org/x/net from v0.17.0 to v0.23.0

## [v1.1.0] - 2024-03-26
### Features
* Functionality to report API endpoints of the application
### Bug fixes
* Updated permissions for file/directory created by security agent
### Miscellaneous chores
* Bumped google.golang.org/protobuf from v1.32.0 to v1.33.0
* Improved logging.

## [v1.0.0] - 2024-02-07
### Changes
* Added env variable to print logs on stdout.
### Miscellaneous chores
* Improved logging.
* Updated software license to New Relic Software License Version 1.0
* Updated Copyright headers.
* Updated license in readme.

## [v0.7.0] - 2024-01-25
### Changes
* Added new critical log messages.
* Added thread pool stats in HC messages.
### Bug Fixes
* Fixed incorrect query parameter encoding.
* Fixed multiple API ID issues for RCE events

## [v0.6.0] - 2024-01-15
### Changes
* Added exclusion based filtering of RXSS events.
* Added ws headers NR-CSEC-ENTITY-GUID and NR-CSEC-ENTITY-NAME.
* Added Support for PUT, PATCH and DELETE http requests type. NR-175410
* Added Support for FastHttp framework.
* Implemented API to send important logs to Security Engine.
* Added support for warning messages in case of missing security wrappers
* Updated jsonVersion to 1.1.1 in security events.
* Updated example/test application directory.
* Updated unit test-cases for mongo.
* Updated file access hook and sent absolute file path.
### Bug Fixes
* Incorrect query type for mongo findAndModify case.
* Fixed empty complete request ID for lastleg .
* Incorrect server protocol in case of grpc.
* Nil query for sql prepared statement for MAC environment.
* Fixed for NPE in case of outbound request.


## [v0.5.1] - 2023-11-16
### Bug Fixes
* Added required changes for backward compatibility with APM agent.

## [v0.5.0] - 2023-10-23 (retracted)

This release was retracted due backward compatibility issue with APM agent

### Features
* Last leg acknowledgement in IAST scanning.
* Added event stats in healthcheck
### Bug Fixes
* Remediate cve with grpc version v1.56.2
* Remediate cve with net version v0.13.0
* Out of Memory issue in case of large request body.
   * Added new security config parameter to set a limit on the read request body.
* Added a few optimizations for CPU and memory utilization.


## [v0.4.0] - 2023-08-28

 * Updated logger module and implemented new logging module with standard golang package `log`
    * Remove the following third-party dependency for logging:
       - juju/fslock
        -  sirupsen/logrus
 * Update HC health check messages sending pipeline and send HC health check messages on priority.
 * Added null parameter checks before event generation.
 * Adopt IAST data pull implementation.
 * Improved logging and added a few fallback mechanisms for restricted environments.
 * Updated service status module and removed the following third-party dependency:
    - juju/fslock
     - mackerelio/go-osstat
     - pbnjay/memory
     -  sirupsen/logrus
     - struCoder/pidusage

 * This affects:
     * Base csec agent code (updated to v0.4.0)
     * `csec_antchfx_htmlquery` instrumentation (updated to v0.4.0)
     * `csec_antchfx_xmlquery` instrumentation (updated to v0.4.0)
     * `csec_augustoroman_v8` instrumentation (updated to v0.4.0)
     * `csec_ldap_v3` instrumentation (updated to v0.4.0)
     * `csec_robertkrimen_otto` instrumentation (updated to v0.4.0)
     * `csec_valyala_fasthttp` instrumentation (updated to v0.4.0)
     * `csec_antchfx_jsonquery` instrumentation (updated to v0.4.0)
     * `csec_antchfx_xpath` instrumentation (updated to v0.4.0)
     * `csec_grpc` instrumentation (updated to v0.4.0)
     * `csec_mongodb_mongo` instrumentation (updated to v0.4.0)

### Support statement
* Go versions 1.18 and later are supported

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
