// Copyright 2023 New Relic Corporation. All rights reserved.
// SPDX-License-Identifier: New Relic Software License v1.0

package security_handlers

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	gorillaWS "github.com/gorilla/websocket"
	logging "github.com/newrelic/csec-go-agent/internal/security_logs"
	secUtils "github.com/newrelic/csec-go-agent/internal/security_utils"
	secConfig "github.com/newrelic/csec-go-agent/security_config"
	eventGeneration "github.com/newrelic/csec-go-agent/security_event_generation"
)

var logger = logging.GetLogger("wsclient")

type eventStruct struct {
	event     []byte
	eventType string
}

type websocket struct {
	conn                 *gorillaWS.Conn
	readcontroller       chan string
	writecontroller      chan string
	isReadThreadRunning  bool
	isWriteThreadRunning bool
	sync.Mutex
	reconnectWill sync.Mutex
	eventBuffer   chan eventStruct
}

func (ws *websocket) isWsConnected() bool {
	return ws.conn != nil
}

func (ws *websocket) pendingEvent() int {
	return len(ws.eventBuffer)
}

func (ws *websocket) clean() {
	for len(ws.eventBuffer) != 0 {
		<-ws.eventBuffer
	}
}

func (ws *websocket) write(s eventStruct) error {
	ws.Lock()
	defer ws.Unlock()
	if !ws.isWsConnected() {
		return errors.New("event discarded due to inactive WebSocket connection")
	}
	return ws.conn.WriteMessage(gorillaWS.TextMessage, s.event)

}

func (ws *websocket) read() ([]byte, error) {
	if !ws.isWsConnected() {
		return nil, errors.New("error reading control command: Inactive WebSocket connection")
	}
	_, message, err := ws.conn.ReadMessage()

	if err != nil && err != io.EOF {
		return message, err
	}
	return message, nil
}

func (ws *websocket) makeConnection() (bool, bool) {
	if ws.isWsConnected() {
		logger.Debugln("webSocket connection already established, skipping new connection initialization")
		return true, false
	}
	ws.Lock()

	var wsDialer = &gorillaWS.Dialer{
		Proxy:            http.ProxyFromEnvironment,
		HandshakeTimeout: 30 * time.Second,
		TLSClientConfig:  createCaCert(),
	}

	validatorEndpoint := secConfig.GlobalInfo.ValidatorServiceUrl()
	conn, res, err := wsDialer.Dial(validatorEndpoint, getConnectionHeader())

	if err != nil || conn == nil {
		logging.PrintInitErrolog("Error connecting to Validator service: Connection failed " + err.Error() + validatorEndpoint)
		logger.Errorln("Error connecting to Validator service: Connection failed ", err.Error(), validatorEndpoint)
		ws.conn = nil
		ws.Unlock()
		secConfig.GlobalInfo.WebSocketConnectionStats.IncreaseConnectionFailure()
		if res != nil {
			if body, _ := io.ReadAll(res.Body); secUtils.CaseInsensitiveContains(string(body), "Invalid License Key!") {
				logger.Debugln("Invalid License Key No need to reconnect")
				return false, false
			}
		}
		return false, true
	} else {
		logger.Infoln("Security Agent is now ACTIVE for ", secConfig.GlobalInfo.ApplicationInfo.GetAppUUID())
		logging.EndStage("4", "Web socket connection to SaaS validator established successfully at "+validatorEndpoint)
		ws.conn = conn
		ws.Unlock()

		logger.Infoln("Initializing WebSocket worker goroutine...")
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
		logger.Infoln("Sleeping for", sleeptimeForReconnect, " before attempting to reconnect")
		time.Sleep(sleeptimeForReconnect)
		logger.Infoln("Sleep end, retrying connection with Validator service")

		if ws.isWsConnected() {
			break
		}
		ok, reconnect := ws.makeConnection()
		if ok || !reconnect {
			secConfig.GlobalInfo.WebSocketConnectionStats.IncreaseConnectionReconnected()
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
		logger.Infoln("Sleeping for", sleeptimeForReconnect, " before attempting to reconnect")
		time.Sleep(sleeptimeForReconnect)
		logger.Infoln("Sleep end, retrying connection with Validator service")
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
	FuzzHandler.IASTCleanUp()
	ws.clean()
	ws.Unlock()
}

func (ws *websocket) RegisterEvent(s []byte, eventID string, eventType string) {

	secConfig.GlobalInfo.EventStats.IncreaseEventSubmittedCount(eventType)
	if !ws.isWsConnected() && eventType != "LogMessage" {
		secConfig.GlobalInfo.EventStats.IncreaseEventRejectedCount(eventType)
		logger.Debugln("Drop event WS not connected or Reconnecting", len(ws.eventBuffer), cap(ws.eventBuffer))
		return
	}

	select {
	case ws.eventBuffer <- eventStruct{event: s, eventType: eventType}:
		logger.Debugln("Added EVENT", len(ws.eventBuffer), " ", cap(ws.eventBuffer))
	default:
		if eventID != "" {
			FuzzHandler.RemoveCompletedRequestIds(eventID)
		}
		secConfig.GlobalInfo.EventStats.IncreaseEventRejectedCount(eventType)
		logger.Errorln("cring.Full : Unable to add event to cring ", len(ws.eventBuffer), cap(ws.eventBuffer))
	}
}

func (ws *websocket) SendPriorityEvent(s []byte) {
	secConfig.GlobalInfo.EventStats.IncreaseEventSubmittedCount("PriorityEvent")
	if !ws.isWsConnected() {
		secConfig.GlobalInfo.EventStats.IncreaseEventRejectedCount("PriorityEvent")
		logger.Debugln("Drop priority event WS not connected or Reconnecting", len(ws.eventBuffer), cap(ws.eventBuffer))
		return
	}
	if logger.IsDebug() {
		logger.Debugln("priority event send", string(s))
	}
	err := ws.write(eventStruct{event: s, eventType: "PriorityEvent"})
	if err != nil {
		secConfig.GlobalInfo.EventStats.IncreaseEventErrorCount("PriorityEvent")
		logger.Errorln("Failed to send event over websocket : ", err.Error())
	} else {
		secConfig.GlobalInfo.EventStats.IncreaseEventCompletedCount("PriorityEvent")
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
	secConfig.GlobalInfo.WebSocketConnectionStats.IncreaseReceivedReconnectAtWill()

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

func (ws *websocket) AddCompletedRequests(parentId, apiID string) {
	FuzzHandler.AppendCompletedRequestIds(parentId, apiID)
}

func (ws *websocket) PendingEvent() int {
	return ws.pendingEvent()
}
func (ws *websocket) PendingFuzzTask() uint64 {
	if FuzzHandler.threadPool == nil {
		return 0
	}
	return uint64(FuzzHandler.threadPool.PendingTask())
}

func InitializeWsConnecton() {
	ws := new(websocket)
	ws.eventBuffer = make(chan eventStruct, 10240)
	ws.readcontroller = make(chan string, 10)
	ws.writecontroller = make(chan string, 10)
	secConfig.SecureWS = ws
	if ws.connect() {
		go eventGeneration.InitHcScheduler()
		go eventGeneration.InitPanicReportScheduler()
	}
}

// Read,Write Threads
func writeThread(ws *websocket) {
	logger.Info("WebSocket write thread started")
	ws.isWriteThreadRunning = true
	defer func() {
		ws.isWriteThreadRunning = false
		logger.Info("WebSocket write thread stopped")
	}()
	for {
		select {
		case <-ws.writecontroller:
			return
		case event := <-ws.eventBuffer:
			err := ws.write(event)
			if err != nil {
				logger.Errorln("Failed to send event over websocket : ", err.Error())
				secConfig.GlobalInfo.EventStats.IncreaseEventErrorCount(event.eventType)
				secConfig.GlobalInfo.WebSocketConnectionStats.IncreaseConnectionFailure()
			} else {
				logger.Debugln("Event sent event over websocket done")
				secConfig.GlobalInfo.WebSocketConnectionStats.IncreaseMessagesSent()
				secConfig.GlobalInfo.EventStats.IncreaseEventCompletedCount(event.eventType)
			}
		}
	}
}

func readThread(ws *websocket) {
	logger.Info("WebSocket read thread started")
	ws.isReadThreadRunning = true
	defer func() {
		ws.isReadThreadRunning = false
		logger.Info("WebSocket read thread stopped")
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
		secConfig.GlobalInfo.WebSocketConnectionStats.IncreaseMessagesReceived()
		err, _ = parseControlCommand(buf)
		if err != nil {
			eventGeneration.SendLogMessage("Unable to unmarshall control command"+err.Error(), "security_handlers", "SEVERE")
			logger.Errorln("Unable to unmarshall cc ", err)
		}
	}
}

// Utils
func getConnectionHeader() http.Header {

	connectionHeader := http.Header{
		"NR-CSEC-CONNECTION-TYPE":         []string{"LANGUAGE_COLLECTOR"},
		"NR-LICENSE-KEY":                  []string{secConfig.GlobalInfo.ApplicationInfo.GetApiAccessorToken()},
		"NR-AGENT-RUN-TOKEN":              []string{secConfig.GlobalInfo.MetaData.GetAgentRunId()},
		"NR-CSEC-VERSION":                 []string{secUtils.CollectorVersion},
		"NR-CSEC-COLLECTOR-TYPE":          []string{secUtils.CollectorType},
		"NR-CSEC-MODE":                    []string{secConfig.GlobalInfo.SecurityMode()},
		"NR-CSEC-APP-UUID":                []string{secConfig.GlobalInfo.ApplicationInfo.GetAppUUID()},
		"NR-CSEC-BUILD-NUMBER":            []string{secUtils.BuildNumber},
		"NR-CSEC-JSON-VERSION":            []string{secUtils.JsonVersion},
		"NR-ACCOUNT-ID":                   []string{secConfig.GlobalInfo.MetaData.GetAccountID()},
		"NR-CSEC-IAST-DATA-TRANSFER-MODE": []string{"PULL"},
		"NR-CSEC-ENTITY-GUID":             []string{secConfig.GlobalInfo.MetaData.GetEntityGuid()},
		"NR-CSEC-ENTITY-NAME":             []string{secConfig.GlobalInfo.MetaData.GetEntityName()},
		"NR-CSEC-IGNORED-VUL-CATEGORIES":  []string{strings.Join(skipDetectionheader(), ",")},
	}

	printConnectionHeader(connectionHeader)
	return connectionHeader
}

func printConnectionHeader(header http.Header) {
	for i, j := range header {
		if i == "NR-LICENSE-KEY" {
			logger.Infoln("Adding WS connection header:", i, "->", "redacted")
		} else {
			logger.Infoln("Adding WS connection header:", i, "->", strings.Join(j, ""))
		}
	}
}

func createCaCert() *tls.Config {
	caCertPool, err := x509.SystemCertPool()
	if err != nil {
		logger.Errorln("erro while createing CA certificate:", err)
		return nil
	}
	caCert := []byte(secUtils.CaCert)
	envCert := os.Getenv("NEW_RELIC_SECURITY_CA_BUNDLE_PATH")
	if envCert != "" {
		caCert, err = os.ReadFile(envCert)
		if err != nil {
			logger.Errorln(err, "using default CA certificate ")
			caCert = []byte(secUtils.CaCert)
		}
	}
	caCertPool.AppendCertsFromPEM(caCert)
	return &tls.Config{RootCAs: caCertPool}
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

func skipDetectionheader() []string {
	var category_map []string

	if secConfig.GlobalInfo.IsInsecureSettingsEnabled() {
		category_map = append(category_map, "CRYPTO", "HASH", "RANDOM", "SECURE_COOKIE", "TRUSTBOUNDARY")
	}
	if secConfig.GlobalInfo.IsInvalidFileAccessEnabled() {
		category_map = append(category_map, "FILE_OPERATION", "FILE_INTEGRITY")
	}
	if secConfig.GlobalInfo.IsSQLInjectionEnabled() {
		category_map = append(category_map, "SQL_DB_COMMAND")
	}
	if secConfig.GlobalInfo.IsNosqlInjectionEnabled() {
		category_map = append(category_map, "NOSQL_DB_COMMAND")
	}
	if secConfig.GlobalInfo.IsLdapInjectionEnabled() {
		category_map = append(category_map, "LDAP")
	}
	if secConfig.GlobalInfo.IsJavascriptInjectionEnabled() {
		category_map = append(category_map, "JAVASCRIPT_INJECTION")
	}
	if secConfig.GlobalInfo.IsCommandInjectionEnabled() {
		category_map = append(category_map, "SYSTEM_COMMAND")
	}
	if secConfig.GlobalInfo.IsXpathInjectionEnabled() {
		category_map = append(category_map, "XPATH")
	}
	if secConfig.GlobalInfo.IsSsrfEnabled() {
		category_map = append(category_map, "HTTP_REQUEST")
	}
	if secConfig.GlobalInfo.IsRxssEnabled() {
		category_map = append(category_map, "REFLECTED_XSS")
	}

	return category_map
}
