module github.com/newrelic/csec-go-agent

go 1.18

require (
	github.com/dlclark/regexp2 v1.9.0
	github.com/gorilla/websocket v1.5.0
	github.com/k2io/hookingo v1.0.5
	golang.org/x/crypto v0.22.0
	github.com/robfig/cron v1.2.0
)

retract v0.5.0 // backward compatibility error corrected in v0.5.1