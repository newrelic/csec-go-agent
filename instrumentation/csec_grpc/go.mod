module github.com/newrelic/csec-go-agent/instrumentation/csec_grpc

go 1.17

require (
	github.com/golang/protobuf v1.5.3
	github.com/newrelic/csec-go-agent v1.0.0
	google.golang.org/grpc v1.58.3
	google.golang.org/protobuf v1.33.0
)

require golang.org/x/net v0.17.0 // indirect

require (
	github.com/dlclark/regexp2 v1.9.0 // indirect
	github.com/gorilla/websocket v1.5.0 // indirect
	github.com/k2io/hookingo v1.0.5 // indirect
	golang.org/x/arch v0.4.0 // indirect
	golang.org/x/sys v0.13.0 // indirect
	golang.org/x/text v0.13.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20230711160842-782d3b101e98 // indirect
)

exclude golang.org/x/net v0.9.0
