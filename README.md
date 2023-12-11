# The New Relic Security Agent for Go is in preview and licensed under the New Relic Pre-Release Software Notice.

##### Repo : [newrelic/csec-go-agent ](https://github.com/newrelic/csec-go-agent)

##### Package Name: newrelic_security_agent
#
The New Relic security agent for Go is in preview and is not generally available.This module enables instrumentation of golang application for interactive application security analysis (IAST) and exposes exploitable vulnerabilities. 
The IAST capability should only be used in pre-production environments as the application is tested for real exploitable vulnerabilities.

# Installation
#### Compatibility and Requirements
For the latest version of the agent, Go 1.17+ is required.
Linux, MacOS, and Windows are supported


#### Installing and using the Go agent
To install the agent, follow the instructions in our [GETTING_STARTED](https://github.com/newrelic/csec-go-agent/blob/main/GETTING_STARTED.md) document.

# Getting Started
examples/server/main.go is an example that will appear as "Example App" in your New Relic applications list. To run it:

```
env NEW_RELIC_LICENSE_KEY=__YOUR_NEW_RELIC_LICENSE_KEY__LICENSE__ \
    go run examples/server/main.go
```
## Support Matrix

### Go Versions

For the latest version of the agent, Go 1.17+ is required.

### Service Frameworks

* net/http
* gin-gonic/gin
* gorilla/mux
* google.golang.org/grpc
* labstack/echo
* julienschmidt/httprouter
* micro/go-micro

### Databases

* database/sql
* mattn/go-sqlite3
* jmoiron/sqlx
* go-mssqldb
* mongodb/mongo-go-driver
* go-sql-driver/mysql
* lib/pq
* jackc/pgx
* jackc/pgx/v5

### Instrumentation Packages

The following [instrumentation packages](https://github.com/newrelic/csec-go-agent/tree/main/instrumentation) extend the base newrelic csec-go-agent package to support the following frameworks and libraries.

Based on additional packages imported by the user application, add suitable imports.

#### Service Frameworks

| Project | Instrumentation Package |
| ------------- | ------------- |
| [antchfx/htmlquery](https://github.com/antchfx/htmlquery) | [instrumentation/csec_antchfx_htmlquery](https://github.com/newrelic/csec-go-agent/tree/main/instrumentation/csec_antchfx_htmlquery)
| [antchfx/jsonquery](https://github.com/antchfx/xmlquery) | [instrumentation/csec_antchfx_jsonquery](https://github.com/newrelic/csec-go-agent/tree/main/instrumentation/csec_antchfx_jsonquery)
| [antchfx/xmlquery](https://github.com/antchfx/xmlquery) | [instrumentation/csec_antchfx_xmlquery](https://github.com/newrelic/csec-go-agent/tree/main/instrumentation/csec_antchfx_xmlquery)
| [antchfx/xpath](https://github.com/antchfx/xpath) | [instrumentation/csec_antchfx_xpath](https://github.com/newrelic/csec-go-agent/tree/main/instrumentation/csec_antchfx_xpath)
| [augustoroman/v8](https://github.com/augustoroman/v8) | [instrumentation/csec_augustoroman_v8](https://github.com/newrelic/csec-go-agent/tree/main/instrumentation/csec_augustoroman_v8)
| [google.golang.org/grpc](https:/google.golang.org/grpc) | [instrumentation/csec_grpc](https://github.com/newrelic/csec-go-agent/tree/main/instrumentation/csec_grpc)
| [ldap/v3](github.com/go-ldap/ldap/v3) | [instrumentation/csec_ldap_v3](https://github.com/newrelic/csec-go-agent/tree/main/instrumentation/csec_ldap_v3)
| [mongo-driver/mongo](https://go.mongodb.org/mongo-driver/mongo) | [instrumentation/csec_mongodb_mongo](https://github.com/newrelic/csec-go-agent/tree/main/instrumentation/csec_mongodb_mongo)
| [robertkrimen/otto](https://github.com/robertkrimen/otto) | [instrumentation/csec_robertkrimen_otto](https://github.com/newrelic/csec-go-agent/tree/main/instrumentation/csec_robertkrimen_otto)
| [valyala/fasthttp](https://github.com/valyala/fasthttp) | [instrumentation/csec_valyala_fasthttp](https://github.com/newrelic/csec-go-agent/tree/main/instrumentation/csec_valyala_fasthttp)

# Support
New Relic hosts and moderates an online forum where you can interact with New Relic employees as well as other customers to get help and share best practices. You can find this project’s topic/threads here: Add the url for the support thread here: https://forum.newrelic.com/s/

# Contribute
Any feedback provided to New Relic about the New Relic csec-go-agent, including feedback provided as source code, comments, or other copyrightable or patentable material, is provided to New Relic under the terms of the Apache Software License, version 2. If you do not provide attribution information or a copy of the license with your feedback, you waive the performance of those requirements of the Apache License with respect to New Relic. The license grant regarding any feedback is irrevocable and persists past the termination of the preview license.
Keep in mind that when you submit a pull request or other feedback, you’ll need to sign the CLA via the click-through using CLA-Assistant. You only have to sign the CLA one time per project.
If you have any questions drop us an email at opensource@newrelic.com.

**A note about vulnerabilities**

As noted in our [security policy](https://github.com/newrelic/csec-go-agent/security/policy), New Relic is committed to the privacy and security of our customers and their data. We believe that providing coordinated disclosure by security researchers and engaging with the security community are important means to achieve our security goals.

If you believe you have found a security vulnerability in this project or any of New Relic's products or websites, we welcome and greatly appreciate you reporting it to New Relic through [HackerOne](https://hackerone.com/newrelic).

If you would like to contribute to this project, review [these guidelines](https://github.com/newrelic/csec-go-agent/blob/main/Contributing%20Feedback.md).

# License

newrelic/csec-go-agent is licensed under the New Relic Software Notice. 
The newrelic/csec-go-agent also uses source code from third-party libraries. You can find full details on which libraries are used and the terms under which they are licensed in the third-party notices document.
