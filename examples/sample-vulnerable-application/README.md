#### examples/sample-vulnerable-application
sample-vulnerable-application is a vulnerable web application designed for demo and reference.
#### WARNING!
---
sample-vulnerable-application is a vulnerable web application.

**Use it for demo purposes only, run it only on test environment.**

#### Setup
```
git clone https://github.com/newrelic/csec-go-agent.git
cd examples/sample-vulnerable-application

```
#### Install dependency packages

```
go mod init test
go mod download 
```

#### Run application
```
go run main.go
```

#### Accessing the application :
The application can be accessed at `http://HOST_MACHINE_IP:8000`