# Getting Started

## Step 1: Installation of go-agent
  Instrument your application with go-agent
  
  https://github.com/newrelic/go-agent/blob/master/GETTING_STARTED.md


## Step 2: Import and add [nrsecurityagent](https://github.com/newrelic/go-agent/tree/master/v3/integrations/nrsecurityagent) dependency in application
Add security agent

```
go get github.com/newrelic/go-agent/v3/integrations/nrsecurityagent 

```
Then import the package in your application:

```
import "github.com/newrelic/go-agent/v3/integrations/nrsecurityagent"

```

### Step 2.1: Create an Application

Instantiate your application by running the following:
```
app, err := newrelic.NewApplication(
    newrelic.ConfigAppName("Your Application Name"),
    newrelic.ConfigLicense("NEW_RELIC_LICENSE_KEY"),
    newrelic.ConfigDebugLogger(os.Stdout),
)
```

After instantiating your app, Init nrsecurityagent as given below

```
    err := nrsecurityagent.InitSecurityAgent(
        app,
       	nrsecurityagent.ConfigSecurityMode("IAST"),
        nrsecurityagent.ConfigSecurityValidatorServiceEndPointUrl("wss://csec.nr-data.net"),
        nrsecurityagent.ConfigSecurityEnable(true),
    )
```

If you are opening an HTTP protocol endpoint, place the newrelic.WrapListen function around the endpoint name to enable vulnerability scanning against that endpoint. For example:

Note: Skip this step if you are on linux environment.
```
    http.ListenAndServe(newrelic.WrapListen(":8000"), nil)
```

Generate traffic against your application for the IAST agent to detect vulnerabilities. Once vulnerabilities are detected they will be reported in the vulnerabilities list.