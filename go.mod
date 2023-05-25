module github.com/newrelic/csec-go-agent

go 1.17

require (
	github.com/dlclark/regexp2 v1.9.0
	github.com/gorilla/websocket v1.5.0
	github.com/k2io/hookingo v1.0.2
	github.com/struCoder/pidusage v0.2.1
)

require (
	golang.org/x/arch v0.3.0 // indirect
	golang.org/x/sys v0.7.0 // indirect
	gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c // indirect
	github.com/stretchr/testify v1.8.2 // indirect
)

exclude (
	golang.org/x/sys v0.0.0-20191026070338-33540a1f6037 // indirect
	golang.org/x/sys v0.0.0-20220715151400-c0bba94af5f8 // indirect
	github.com/stretchr/testify v1.7.1 // indirect
	github.com/stretchr/testify v1.7.0 // indirect
)