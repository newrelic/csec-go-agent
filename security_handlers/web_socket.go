// Copyright 2023 New Relic Corporation. All rights reserved.
// SPDX-License-Identifier: New Relic Pre-Release

package security_handlers

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"io/ioutil"
	"math/rand"
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

const validatorDefaultEndpoint = "wss://csec.nr-data.net"

type websocket struct {
	conn                 *gorillaWS.Conn
	readcontroller       chan string
	writecontroller      chan string
	isReadThreadRunning  bool
	isWriteThreadRunning bool
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
		logger.Debugln("Websocket connection already initialized : Skip")
		eventGeneration.SendApplicationInfo() // sending updated appinfo
		return true, false
	}
	ws.Lock()
	validatorEndpoint := ""
	if validatorEndpoint = secConfig.GlobalInfo.ValidatorServiceUrl(); validatorEndpoint == "" {
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
		logging.PrintInitErrolog("Failed to connect Validator " + validatorEndpoint)
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
		logging.PrintInitlog("Connected to Prevent-Web service at : " + validatorEndpoint)
		logger.Infoln("K.Reconnect init k.Conn successful", validatorEndpoint)
		ws.conn = conn
		ws.Unlock()

		logger.Infoln("Security Agent is now ACTIVE for ", secConfig.GlobalInfo.ApplicationInfo.GetAppUUID())
		logger.Infoln("!!! Websocket worker goroutine starting...")
		logging.EndStage("4", "Web socket connection to SaaS validator established successfully")
		ws.flushWsController()
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

		sleeptimeForReconnect := time.Duration(rand.Intn(10)+5) * time.Second
		logger.Infoln("sleeping before reconnecting", sleeptimeForReconnect)
		time.Sleep(sleeptimeForReconnect)
		logger.Infoln("sleep end, retrying to connect with validator")

		if ws.isWsConnected() {
			break
		}
		ok, reconnect := ws.makeConnection()
		if ok || !reconnect {
			return
		}

	}
}

func (ws *websocket) connect() bool {
	for !ws.isWsConnected() {
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
		sleeptimeForReconnect := time.Duration(rand.Intn(10)+5) * time.Second
		logger.Infoln("sleeping before reconnecting", sleeptimeForReconnect)
		time.Sleep(sleeptimeForReconnect)
		logger.Infoln("sleep end, retrying to connect with validator")
	}
	return true
}

func (ws *websocket) closeWs() {
	logger.Infoln("!!! Close Websocket Connection !!! ", len(ws.eventBuffer), " ", cap(ws.eventBuffer))
	logger.Infoln("Close Read/Write Thread")
	if ws.isWriteThreadRunning {
		logger.Infoln("Send closeWrite thread signal")
		ws.writecontroller <- "close"
	}
	if ws.isReadThreadRunning {
		logger.Infoln("Send closeRead thread signal")
		ws.readcontroller <- "close"
	}
	ws.Lock()
	if ws.conn != nil {
		ws.conn.Close()
	}
	ws.conn = nil
	ws.Unlock()
}

func (ws *websocket) RegisterEvent(s []byte) {
	increaseEventProcessed(s)
	if !ws.isWsConnected() {
		increaseEventDropCount(s)
		logger.Debugln("Drop event WS not connected or Reconnecting", len(ws.eventBuffer), cap(ws.eventBuffer))
		return
	}
	select {
	case ws.eventBuffer <- s:
		logger.Debugln("Added EVENT", len(ws.eventBuffer), " ", cap(ws.eventBuffer))
	default:
		increaseEventDropCount(s)
		logger.Errorln("cring.Full : Unable to add event to cring ", len(ws.eventBuffer), cap(ws.eventBuffer))
	}
}

func (ws *websocket) SendPriorityEvent(s []byte) {
	if !ws.isWsConnected() {
		logger.Debugln("Drop priority event WS not connected or Reconnecting", len(ws.eventBuffer), cap(ws.eventBuffer))
		return
	}
	logger.Debugln("priority event send", string(s))
	ws.write(s)
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
	if !ws.reconnectWill.TryLock() {
		logger.Infoln("No need to reconnect another thread is doing a reconnection")
		return
	}
	if secConfig.GlobalInfo.IsIASTEnable() {
		for FuzzHandler.threadPool != nil && !FuzzHandler.threadPool.IsTaskPoolEmpty() {
			logger.Debugln("wait for fuzz threadPool empty")
			time.Sleep(100 * time.Millisecond)
		}
	}
	secConfig.GlobalInfo.SetSecurityEnabled(false)

	// for ws.pendingEvent() > 0 {
	// 	logger.Debugln("wait for event threadPool empty")
	// 	time.Sleep(100 * time.Millisecond)
	// }

	//reset ws connection

	ws.closeWs()
	ws.reconnect()

	secConfig.GlobalInfo.SetSecurityEnabled(true)
	ws.reconnectWill.Unlock()
}

func (ws *websocket) ReconnectAtAgentRefresh() {
	if !ws.reconnectWill.TryLock() {
		logger.Infoln("No need to reconnect another thread is doing a reconnection")
		return
	}
	secConfig.GlobalInfo.SetSecurityEnabled(false)
	//reset ws connection
	ws.closeWs()
	ws.reconnect()
	secConfig.GlobalInfo.SetSecurityEnabled(true)
	ws.reconnectWill.Unlock()
}

func InitializeWsConnecton() {
	ws := new(websocket)
	ws.eventBuffer = make(chan []byte, 10240)
	ws.readcontroller = make(chan string, 10)
	ws.writecontroller = make(chan string, 10)
	secConfig.SecureWS = ws
	if ws.connect() {
		go eventGeneration.InitHcScheduler()
	}
}

// Read,Write Threads
func writeThread(ws *websocket) {
	logger.Info("Start ws write Thread")
	ws.isWriteThreadRunning = true
	defer func() {
		ws.isWriteThreadRunning = false
		logger.Info("Close ws write Thread")
	}()
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
	ws.isReadThreadRunning = true
	defer func() {
		ws.isReadThreadRunning = false
		logger.Info("Close ws read Thread")
	}()
	for {
		buf, err := ws.read()
		if err != nil {
			select {
			case <-ws.readcontroller:
				logger.Debugln("Websocket err at agent restart " + err.Error())
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
		"NR-CSEC-CONNECTION-TYPE":         []string{"LANGUAGE_COLLECTOR"},
		"NR-LICENSE-KEY":                  []string{secConfig.GlobalInfo.ApplicationInfo.GetApiAccessorToken()},
		"NR-AGENT-RUN-TOKEN":              []string{secConfig.GlobalInfo.MetaData.GetAccountID()},
		"NR-CSEC-VERSION":                 []string{secUtils.CollectorVersion},
		"NR-CSEC-COLLECTOR-TYPE":          []string{secUtils.CollectorType},
		"NR-CSEC-MODE":                    []string{secConfig.GlobalInfo.SecurityMode()},
		"NR-CSEC-APP-UUID":                []string{secConfig.GlobalInfo.ApplicationInfo.GetAppUUID()},
		"NR-CSEC-BUILD-NUMBER":            []string{secUtils.BuildNumber},
		"NR-CSEC-JSON-VERSION":            []string{secUtils.JsonVersion},
		"NR-ACCOUNT-ID":                   []string{secConfig.GlobalInfo.MetaData.GetAccountID()},
		"NR-CSEC-IAST-DATA-TRANSFER-MODE": []string{"PULL"},
	}

}

func increaseEventProcessed(event []byte) {
	if !secUtils.CaseInsensitiveContains(string(event), `"jsonName":"Event"`) {
		return
	}
	secConfig.GlobalInfo.EventData.IncreaseEventProcessed()
}

func increaseEventDropCount(event []byte) {
	if !secUtils.CaseInsensitiveContains(string(event), `"jsonName":"Event"`) {
		return
	}
	secConfig.GlobalInfo.EventData.IncreaseEventDropCount()
}

func increaseEventEventSentCount(event []byte) {
	if !secUtils.CaseInsensitiveContains(string(event), `"jsonName":"Event"`) {
		return
	}
	secConfig.GlobalInfo.EventData.IncreaseEventSentCount()
}

func (ws *websocket) flushWsController() {
	logger.Debugln("Flush flush Ws Controller Buffer", len(ws.readcontroller))
	for ws.readcontroller != nil && len(ws.readcontroller) > 0 {
		<-ws.readcontroller
	}
	for ws.writecontroller != nil && len(ws.writecontroller) > 0 {
		<-ws.writecontroller
	}
}
