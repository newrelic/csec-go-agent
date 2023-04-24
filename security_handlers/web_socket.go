// Copyright 2022 New Relic Corporation. All rights reserved.

package security_handlers

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"io/ioutil"
	"math"
	"net/http"
	"os"
	"sync"
	"time"

	gorillaWS "github.com/gorilla/websocket"
	logging "github.com/newrelic/csec-go-agent/internal/security_logs"
	secUtils "github.com/newrelic/csec-go-agent/internal/security_utils"
	secConfig "github.com/newrelic/csec-go-agent/security_config"
	eventGeneration "github.com/newrelic/csec-go-agent/security_event_generation"
)

var logger = logging.GetLogger("wsclient")

const validatorDefaultEndpoint = "ws://localhost:54321/"

type websocket struct {
	conn            *gorillaWS.Conn
	readcontroller  chan string
	writecontroller chan string
	sync.Mutex
	reconnectWill sync.Mutex
	eventBuffer   chan []byte
}

func (ws *websocket) isWsConnected() bool {
	return ws.conn != nil
}

func (ws *websocket) pendingEvent() int {
	return len(ws.eventBuffer)
}

func (ws *websocket) write(s []byte) bool {
	ws.Lock()
	defer ws.Unlock()
	if !ws.isWsConnected() {
		return false
	}
	err := ws.conn.WriteMessage(gorillaWS.TextMessage, s)
	if err != nil {
		logger.Errorln("Failed to send event over websocket : ", err.Error())
		increaseEventDropCount(s)
		return false
	}
	increaseEventEventSentCount(s)
	logger.Debugln("Event sent event over websocket done")
	return true
}

func (ws *websocket) read() ([]byte, error) {

	if !ws.isWsConnected() {
		return nil, errors.New("Failed to read CC over websocket ,ws is not connected")
	}
	_, message, err := ws.conn.ReadMessage()
	if err != nil && err != io.EOF {
		return message, err
	}
	return message, nil
}

func (ws *websocket) makeConnection() (bool, bool) {
	if ws.isWsConnected() {
		logging.PrintInitlog("Websocket connection already initialized : Skip", "WS")
		eventGeneration.SendApplicationInfo() // sending updated appinfo
		return true, false
	}
	ws.Lock()
	validatorEndpoint := ""
	if validatorEndpoint = secConfig.GlobalInfo.Security.Validator_service_url; validatorEndpoint == "" {
		validatorEndpoint = validatorDefaultEndpoint
	}
	connectionHeader := getConnectionHeader()

	var wsDialer = &gorillaWS.Dialer{
		Proxy:            http.ProxyFromEnvironment,
		HandshakeTimeout: 30 * time.Second,
	}
	caCertPool, err := x509.SystemCertPool()
	if err != nil {
		logger.Errorln(err)
		ws.Unlock()
		return false, false
	}
	caCert := []byte(secUtils.CaCert)

	envCert := os.Getenv("NEW_RELIC_SECURITY_CA_BUNDLE_PATH")
	if envCert != "" {
		caCert, err = ioutil.ReadFile(envCert)
		if err != nil {
			logger.Errorln(err, "unsing default caCert")
			caCert = []byte(secUtils.CaCert)
		}
	}
	caCertPool.AppendCertsFromPEM(caCert)
	wsDialer.TLSClientConfig = &tls.Config{RootCAs: caCertPool}

	conn, res, err := wsDialer.Dial(validatorEndpoint, connectionHeader)
	if err != nil || conn == nil {
		logging.PrintInitErrolog("Failed to connect Validator ", validatorEndpoint)
		logger.Errorln("Failed to connect Validator  : ", err, validatorEndpoint)
		ws.conn = nil
		ws.Unlock()
		if res != nil {
			if body, _ := ioutil.ReadAll(res.Body); secUtils.CaseInsensitiveContains(string(body), "Invalid License Key!") {
				logger.Debugln("Invalid License Key No need to reconnect")
				return false, false
			}
		}
		return false, true
	} else {
		logging.PrintInitlog("Connected to Prevent-Web service at : "+validatorEndpoint, "WS")
		logger.Infoln("K.Reconnect init k.Conn successful", validatorEndpoint)
		ws.conn = conn
		ws.Unlock()

		logger.Infoln("Collector is now active for", secConfig.GlobalInfo.ApplicationInfo.AppUUID)
		logger.Infoln("!!! Websocket worker goroutine starting...")
		logging.EndStage("4", "WS")

		go writeThread(ws)
		go readThread(ws)
		eventGeneration.SendApplicationInfo()
		return true, false
	}
}

func (ws *websocket) reconnect() {
	for {
		if ws.isWsConnected() {
			break
		}
		ok, reconnect := ws.makeConnection()
		if ok || !reconnect {
			return
		}
		sleeptimeForReconnect := 15 * time.Second
		logger.Infoln("sleeping before reconnecting", sleeptimeForReconnect)
		time.Sleep(sleeptimeForReconnect)
		logger.Infoln("sleep end, retrying to connect with validator")

	}
}

func (ws *websocket) connect() bool {
	waitTime := 1
	for !ws.isWsConnected() {
		if waitTime >= 6 {
			return false
		}
		if ws.isWsConnected() {
			break
		}
		ok, reconnect := ws.makeConnection()
		if ok {
			return true
		}
		if !reconnect {
			return false
		}
		sleeptimeForReconnect := time.Duration(waitTime) * time.Minute
		logger.Infoln("sleeping before reconnecting", sleeptimeForReconnect)
		time.Sleep(sleeptimeForReconnect)
		logger.Infoln("sleep end, retrying to connect with validator")
		waitTime++
	}
	return true
}

func (ws *websocket) closeWs() {
	logger.Infoln("!!! Close Websocket Connection !!! ", len(ws.eventBuffer), " ", cap(ws.eventBuffer))
	logger.Infoln("Close Read/Write Thread")
	ws.writecontroller <- "close"
	ws.readcontroller <- "close"
	//close(ws.readcontroller)

	ws.Lock()
	if ws.conn != nil {
		ws.conn.Close()
	}
	ws.conn = nil
	ws.Unlock()
}

func (ws *websocket) RegisterEvent(s []byte) {
	increaseEventProcessed(s)
	select {
	case ws.eventBuffer <- s:
		logger.Debugln("Added EVENT", len(ws.eventBuffer), " ", cap(ws.eventBuffer))
	default:
		increaseEventDropCount(s)
		logger.Errorln("cring.Full : Unable to add event to cring ", len(ws.eventBuffer), cap(ws.eventBuffer))
	}
}

func (ws *websocket) GetStatus() bool {
	return ws.isWsConnected()
}

//Public Methods

func (ws *websocket) CloseWSConnection() {
	ws.closeWs()
}

func (ws *websocket) ReconnectAtWill() {
	/*
	 * 1. Mark LC in reconnecting phase
	 * 2. Let IAST request processor ideal out.
	 * 3. Mark LC in inactive state by disconnecting WS connection.
	 * 4. Initiate WS reconnect
	 *
	 * Post reconnect: reset 'reconnecting phase' in WSClient.
	 */
	ws.reconnectWill.Lock()
	if secConfig.GlobalInfo.CurrentPolicy.VulnerabilityScan.Enabled && secConfig.GlobalInfo.CurrentPolicy.VulnerabilityScan.IastScan.Enabled {
		for FuzzHandler.threadPool != nil && !FuzzHandler.threadPool.IsTaskPoolEmpty() {
			logger.Debugln("wait for fuzz threadPool empty")
			time.Sleep(100 * time.Millisecond)
		}
	}
	secConfig.GlobalInfo.Security.Enabled = false

	for ws.pendingEvent() > 0 {
		logger.Debugln("wait for event threadPool empty")
		time.Sleep(100 * time.Millisecond)
	}

	//reset ws connection

	ws.closeWs()
	ws.reconnect()

	secConfig.GlobalInfo.Security.Enabled = true
	ws.reconnectWill.Unlock()
}

func (ws *websocket) ReconnectAtAgentRefresh() {
	ws.reconnectWill.Lock()
	//reset ws connection
	ws.closeWs()
	ws.reconnect()
	ws.reconnectWill.Unlock()
}

func InitializeWsConnecton() {
	logging.NewStage("4", "WS", "Websocket connection")
	ws := new(websocket)
	ws.eventBuffer = make(chan []byte, 10240)
	ws.readcontroller = make(chan string, 10)
	ws.writecontroller = make(chan string)
	secConfig.SecureWS = ws
	if ws.connect() {
		go eventGeneration.InitHcScheduler()
	}
}

// Read,Write Threads
func writeThread(ws *websocket) {
	logger.Info("Start ws write Thread")
	defer logger.Info("Close ws write Thread")
	for {
		select {
		case <-ws.writecontroller:
			return
		case event := <-ws.eventBuffer:
			logger.Debugln("send event", len(ws.eventBuffer), " ", cap(ws.eventBuffer))
			ws.write(event)
		}
	}
}

func readThread(ws *websocket) {
	logger.Info("Start ws read Thread")
	defer logger.Info("Close ws read Thread")
	for {
		buf, err := ws.read()
		if err != nil {
			select {
			case <-ws.readcontroller:
				return
			default:
				logger.Errorln("Failed to read CC over websocket err : " + err.Error())
				go ws.ReconnectAtAgentRefresh()
				return
			}

		}
		err, _ = parseControlCommand(buf)
		if err != nil {
			logger.Errorln("Unable to unmarshall cc ", err)
		}
	}
}

// Utils
func getConnectionHeader() http.Header {
	return http.Header{
		"NR-CSEC-CONNECTION-TYPE": []string{"LANGUAGE_COLLECTOR"},
		"NR-LICENSE-KEY":          []string{secConfig.GlobalInfo.ApplicationInfo.ApiAccessorToken},
		"NR-AGENT-RUN-TOKEN":      []string{secConfig.GlobalInfo.AgentRunId},
		"NR-CSEC-VERSION":         []string{secUtils.CollectorVersion},
		"NR-CSEC-COLLECTOR-TYPE":  []string{secUtils.CollectorType},
		"NR-CSEC-MODE":            []string{secConfig.GlobalInfo.Security.Mode},
		"NR-CSEC-APP-UUID":        []string{secConfig.GlobalInfo.ApplicationInfo.AppUUID},
		"NR-CSEC-BUILD-NUMBER":    []string{secUtils.BuildNumber},
		"NR-CSEC-JSON-VERSION":    []string{secUtils.JsonVersion},
		"NR-ACCOUNT-ID":           []string{secConfig.GlobalInfo.AccountID},
	}

}

func increaseEventProcessed(event []byte) {
	if !secUtils.CaseInsensitiveContains(string(event), `"jsonName":"Event"`) {
		return
	}
	secConfig.GlobalInfo.EventData.EventProcessed++
	if secConfig.GlobalInfo.EventData.EventProcessed == 0 {
		secConfig.GlobalInfo.EventData.EventProcessed = math.MaxUint64
	}
}

func increaseEventDropCount(event []byte) {
	if !secUtils.CaseInsensitiveContains(string(event), `"jsonName":"Event"`) {
		return
	}
	secConfig.GlobalInfo.EventData.EventDropCount++
	if secConfig.GlobalInfo.EventData.EventDropCount == 0 {
		secConfig.GlobalInfo.EventData.EventDropCount = math.MaxUint64
	}
}

func increaseEventEventSentCount(event []byte) {
	if !secUtils.CaseInsensitiveContains(string(event), `"jsonName":"Event"`) {
		return
	}
	secConfig.GlobalInfo.EventData.EventSentCount++
	if secConfig.GlobalInfo.EventData.EventSentCount == 0 {
		secConfig.GlobalInfo.EventData.EventSentCount = math.MaxUint64
	}
}
