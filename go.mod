module github.com/newrelic/csec-go-agent

go 1.18

require (
	github.com/adhocore/gronx v1.19.1
	github.com/dlclark/regexp2 v1.9.0
	github.com/gorilla/websocket v1.5.0
	github.com/k2io/hookingo v1.0.6
	golang.org/x/crypto v0.31.0
)

require (
	golang.org/x/arch v0.4.0 // indirect
	golang.org/x/sys v0.28.0 // indirect
)

retract v0.5.0 // backward compatibility error corrected in v0.5.1
