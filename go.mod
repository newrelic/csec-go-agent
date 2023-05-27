module github.com/newrelic/csec-go-agent

go 1.17

require (
	github.com/dlclark/regexp2 v1.9.0
	github.com/gorilla/websocket v1.5.0
	github.com/juju/fslock v0.0.0-20160525022230-4d5c94c67b4b
	github.com/k2io/hookingo v1.0.3
	github.com/mackerelio/go-osstat v0.2.4
	github.com/pbnjay/memory v0.0.0-20210728143218-7b4eea64cf58
	github.com/sirupsen/logrus v1.9.0
	github.com/struCoder/pidusage v0.2.1
)

require (
	github.com/stretchr/testify v1.8.2 // indirect
	golang.org/x/arch v0.3.0 // indirect
	golang.org/x/sys v0.7.0 // indirect
	gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c // indirect
)

exclude (
	github.com/stretchr/testify v1.7.0 // indirect
	github.com/stretchr/testify v1.7.1 // indirect
	golang.org/x/sys v0.0.0-20191026070338-33540a1f6037 // indirect
	golang.org/x/sys v0.0.0-20220715151400-c0bba94af5f8 // indirect
)