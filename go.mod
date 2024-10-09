module github.com/newrelic/csec-go-agent

go 1.18

require (
	github.com/adhocore/gronx v1.19.1
	github.com/dlclark/regexp2 v1.9.0
	github.com/gorilla/websocket v1.5.0
	github.com/k2io/hookingo v1.0.5
	golang.org/x/crypto v0.22.0
)

retract v0.5.0 // backward compatibility error corrected in v0.5.1