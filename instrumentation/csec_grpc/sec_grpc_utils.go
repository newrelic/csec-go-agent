// Copyright 2023 New Relic Corporation. All rights reserved.
// SPDX-License-Identifier: New Relic Pre-Release

package csec_grpc

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	protoV1 "github.com/golang/protobuf/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
)

type secGrpcHandler struct {
	reqMessagesCount   int
	reqMessages        []string
	isClientStream     bool
	isServerStream     bool
	grcpMessageType    string
	grcpMessageVersion string
	method             string
	reqheaders         []string
}

func (h *secGrpcHandler) getRequestData() ([]byte, error) {
	h.reqMessagesCount++
	if h.reqMessagesCount > len(h.reqMessages) {
		return nil, io.EOF
	}
	if h.reqMessagesCount > 1 {
		time.Sleep(time.Millisecond * 50)
	}
	return []byte(h.reqMessages[h.reqMessagesCount-1]), nil
}

func (h *secGrpcHandler) invokeRpc(cc *grpc.ClientConn) error {

	defer cc.Close()
	if h.isServerStream && h.isClientStream {
		return h.invokeBidi(cc)
	} else if h.isServerStream {
		return h.invokeServerStream(cc)
	} else if h.isClientStream {
		return h.invokeClientStream(cc)
	} else {
		return h.invokeUnary(cc)
	}

}

func (h *secGrpcHandler) invokeUnary(cc *grpc.ClientConn) error {

	req, err := requestData(h)

	if err != nil && err != io.EOF {
		return fmt.Errorf("error getting request data invokeUnary : %v", err)
	}

	md := metadataFromHeaders(h.reqheaders)
	ctx := metadata.NewOutgoingContext(context.Background(), md)

	err = cc.Invoke(ctx, h.method, req, &DummyRes{})

	if err != nil {
		return fmt.Errorf("grpc invokeUnary call for %q failed: %v", h.method, err)
	}
	return nil
}

func (h *secGrpcHandler) invokeClientStream(cc *grpc.ClientConn) error {

	md := metadataFromHeaders(h.reqheaders)
	ctx := metadata.NewOutgoingContext(context.Background(), md)

	sd := grpc.StreamDesc{
		StreamName:    h.method,
		ServerStreams: false,
		ClientStreams: true,
	}
	str, err := cc.NewStream(ctx, &sd, h.method)

	if err != nil {
		return fmt.Errorf("error in creating stream object: %v", err)
	}

	for err == nil {
		var req interface{}
		req, err = requestData(h)

		if err == io.EOF {
			err = CloseAndReceive(str)
			break
		}
		if err != nil {
			return fmt.Errorf("error getting request data: %v", err)
		}

		err = str.SendMsg(req)
		if err == io.EOF {
			err = CloseAndReceive(str)
			break
		}
		if err != nil {
			return fmt.Errorf("error in sending req data: %v", err)
		}

	}
	if err != nil {
		return fmt.Errorf("grpc call for %q failed: %v", h.method, err)
	}
	return nil
}

func (h *secGrpcHandler) invokeServerStream(cc *grpc.ClientConn) error {
	req, err := requestData(h)
	if err != nil && err != io.EOF {
		return fmt.Errorf("error getting request data: %v", err)
	}
	md := metadataFromHeaders(h.reqheaders)
	ctx := metadata.NewOutgoingContext(context.Background(), md)
	ctx, cancel := context.WithCancel(ctx)

	sd := grpc.StreamDesc{
		StreamName:    h.method,
		ServerStreams: true,
		ClientStreams: false,
	}
	str, err := cc.NewStream(ctx, &sd, h.method)
	if err != nil {
		cancel()
		return fmt.Errorf("error in creating NewStream: %v", err)
	} else {
		err = str.SendMsg(req)
		if err != nil {
			cancel()
			return fmt.Errorf("error in sending req data: %v", err)
		}
		err = str.CloseSend()
		if err != nil {
			cancel()
			return err
		}
		go func() {
			<-str.Context().Done()
			cancel()
		}()
	}

	if str != nil {
		if _, err = str.Header(); err == nil {
		}
	}
	for err == nil {
		err = str.RecvMsg(&DummyRes{})
		if err != nil {
			if err == io.EOF {
				err = nil
			}
			break
		}
	}

	if err != nil {
		return fmt.Errorf("grpc call for %q failed: %v", h.method, err)
	}

	return nil

}

func (h *secGrpcHandler) invokeBidi(cc *grpc.ClientConn) error {
	md := metadataFromHeaders(h.reqheaders)
	ctx := metadata.NewOutgoingContext(context.Background(), md)
	ctx, cancel := context.WithCancel(ctx)
	sd := grpc.StreamDesc{
		StreamName:    h.method,
		ServerStreams: true,
		ClientStreams: true,
	}
	str, err := cc.NewStream(ctx, &sd, h.method)
	if err != nil {
		return fmt.Errorf("error in creating NewStream: %v", err)
	}
	var wg sync.WaitGroup
	var sendErr atomic.Value

	defer wg.Wait()
	if err == nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var err error
			for err == nil {
				var req interface{}
				req, err = requestData(h)
				if err == io.EOF {
					err = str.CloseSend()
					break
				}
				if err != nil {
					err = fmt.Errorf("error getting request data: %v", err)
					cancel()
					break
				}
				err = str.SendMsg(req)
			}
			if err != nil {
				sendErr.Store(err)
			}
		}()
	}

	if str != nil {
		if _, err := str.Header(); err == nil {
		}
	}

	for err == nil {
		err = str.RecvMsg(&DummyRes{})
		if err != nil {
			if err == io.EOF {
				err = nil
			}
			break
		}
	}

	if se, ok := sendErr.Load().(error); ok && se != io.EOF {
		err = se
	}

	if err != nil {
		// Error codes sent from the server will get printed differently below.
		// So just bail for other kinds of errors here.
		return fmt.Errorf("grpc call for %q failed: %v", h.method, err)
	}

	return nil

}

func requestData(handler *secGrpcHandler) (interface{}, error) {
	if handler != nil {
		data, err := handler.getRequestData()
		if err != nil {
			return nil, err
		}

		req, err := protoregistry.GlobalTypes.FindMessageByName(protoreflect.FullName(handler.grcpMessageType))
		if err != nil {
			logger.Errorln(err.Error())
			return nil, err
		}
		req1 := req.New().Interface()
		err = protojson.Unmarshal([]byte(data), req1)
		if err != nil {
			return nil, fmt.Errorf("grpc call for %q failed: %v", data, err)
		}
		if handler.grcpMessageVersion == "v1" {
			return protoV1.MessageV1(req1), nil
		}
		return req1, nil
	}
	return nil, fmt.Errorf("handler object can't be null")
}

// refer https://github.com/fullstorydev/grpcurl/blob/master/invoke.go
var base64Codecs = []*base64.Encoding{base64.StdEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.RawURLEncoding}

func decode(val string) (string, error) {
	var firstErr error
	var b []byte
	// we are lenient and can accept any of the flavors of base64 encoding
	for _, d := range base64Codecs {
		var err error
		b, err = d.DecodeString(val)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		return string(b), nil
	}
	return "", firstErr
}

func metadataFromHeaders(headers []string) metadata.MD {
	md := make(metadata.MD)
	for _, part := range headers {
		if part != "" {
			pieces := strings.SplitN(part, ":", 2)
			if len(pieces) == 1 {
				pieces = append(pieces, "") // if no value was specified, just make it "" (maybe the header value doesn't matter)
			}
			headerName := strings.ToLower(strings.TrimSpace(pieces[0]))
			val := strings.TrimSpace(pieces[1])
			if strings.HasSuffix(headerName, "-bin") {
				if v, err := decode(val); err == nil {
					val = v
				}
			}
			md[headerName] = append(md[headerName], val)
		}
	}
	return md
}

type DummyRes struct{}

func (m *DummyRes) Reset() {
	*m = DummyRes{}
}
func (m *DummyRes) String() string {
	return ""
}
func (m *DummyRes) ProtoMessage() {}

func CloseAndReceive(stream grpc.ClientStream) error {
	if err := stream.CloseSend(); err != nil {
		return err
	}
	if err := stream.RecvMsg(&DummyRes{}); err != nil {
		return err
	}
	// make sure we get EOF for a second message
	if err := stream.RecvMsg(&DummyRes{}); err != io.EOF {
		if err == nil {
			return fmt.Errorf("client-streaming method %q returned more than one response message")
		} else {
			return err
		}
	}
	return nil
}
