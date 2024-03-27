module github.com/newrelic/csec-go-agent/instrumentation/csec_grpc

go 1.17

require (
	github.com/newrelic/csec-go-agent v1.1.0
	google.golang.org/grpc v1.58.3
	google.golang.org/protobuf v1.33.0
	github.com/golang/protobuf v1.5.3
)

require(
	golang.org/x/net v0.17.0
)

exclude(
	golang.org/x/net v0.9.0
)