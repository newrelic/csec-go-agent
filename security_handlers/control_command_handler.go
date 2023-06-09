// Copyright 2023 New Relic Corporation. All rights reserved.
// SPDX-License-Identifier: New Relic Pre-Release

package security_handlers

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"

	secConfig "github.com/newrelic/csec-go-agent/security_config"
	eventGeneration "github.com/newrelic/csec-go-agent/security_event_generation"
)

const (
	SHUTDOWN_LANGUAGE_AGENT                      = 1
	UNSUPPORTED_AGENT                            = 5
	EVENT_RESPONSE                               = 6
	OLD_AGENT                                    = 7
	STARTUP_WELCOME_MSG                          = 10
	FUZZ_REQUEST                                 = 11
	RECONNECT_AT_WILL                            = 12
	SEND_POLICY                                  = 100
	POLICY_UPDATE_FAILED_DUE_TO_VALIDATION_ERROR = 102
)

type CCData struct {
	Data interface{} `json:"data"`
}
type ControlComand struct {
	ControlCommand int      `json:"controlCommand"`
	Arguments      []string `json:"arguments"`
}
type ControlComandHandler struct {
	ControlComand
	CCData
}

func parseControlCommand(arg []byte) (error, bool) {

	var cc ControlComandHandler
	err := json.Unmarshal(arg, &cc)

	if err != nil {
		logger.Errorln("Unable to unmarshall cc ", err)
		return errors.New("Unable to unmarshall cc "), false
	}
	logger.Debugln("Recived control command", cc.ControlCommand)

	switch cc.ControlCommand {
	case STARTUP_WELCOME_MSG:
		logger.Infoln("CC10", string(arg))
	case FUZZ_REQUEST:
		if FuzzHandler.threadPool == nil {
			initRestRequestThreadPool()
		}
		if len(cc.Arguments) <= 1 {
			return errors.New("Unable to process cc11, need minimum 2 arguments "), false
		}
		dsFilePath := filepath.Join(secConfig.GlobalInfo.Security.SecurityHomePath, "nr-security-home", "tmp")
		arguments := strings.Replace(cc.Arguments[0], "{{NR_CSEC_VALIDATOR_HOME_TMP}}", dsFilePath, -1)
		arguments = strings.Replace(arguments, "%7B%7BNR_CSEC_VALIDATOR_HOME_TMP%7D%7D", dsFilePath, -1)

		arg := []byte(arguments)
		var cc11 FuzzRequrestHandler
		err = json.Unmarshal(arg, &cc11)
		if err != nil {
			return errors.New("Unable to unmarshall cc11 : " + err.Error()), false
		} else {
			logger.Debugln("Fuzz request received")
			logger.Debugln("will fuzz, parsedOK ..")
			registerFuzzTask(&cc11, cc.Arguments[1])
			break
		}
	case RECONNECT_AT_WILL:
		logger.Info("Received WS 'reconnect' command from server. Initiating sequence.")
		go secConfig.SecureWS.ReconnectAtWill()
		return nil, true

	case SEND_POLICY:
		type policy struct {
			ControlComand
			Data secConfig.Policy `json:"data"`
		}
		var defaultPolicy policy
		err := json.Unmarshal(arg, &defaultPolicy)
		if err != nil {
			logger.Errorln("Unable to unmarshall cc100 ", err)
		} else {
			logger.Debugln("defaultPolicy", defaultPolicy.Data)
			policy := secConfig.UpdateGlobalConf(defaultPolicy.Data, string(arg))
			eventGeneration.SendUpdatedPolicy(policy)

		}
	case POLICY_UPDATE_FAILED_DUE_TO_VALIDATION_ERROR:
		logger.Warnln("Updated policy failed validation. Reverting to default policy for the mode", cc.Data)
		secConfig.InstantiateDefaultPolicy()
	}
	return nil, false
}
