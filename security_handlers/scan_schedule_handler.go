package security_handlers

import (
	"time"

	secConfig "github.com/newrelic/csec-go-agent/security_config"
)

var dealyAgentTill = time.Now()

func StartAgentWithDelay() {
	if secConfig.GlobalInfo.ScanScheduleDelay() > 0 {
		dealyAgentTill = time.Now().Add(time.Duration(secConfig.GlobalInfo.ScanScheduleDelay()) * time.Minute)
		if secConfig.GlobalInfo.ScanScheduleAllowIastSampleCollection() {
			InitializeWsConnecton()
		} else {
			time.Sleep(time.Duration(secConfig.GlobalInfo.ScanScheduleDelay()) * time.Minute)
			InitializeWsConnecton()
		}
	} else {
		InitializeWsConnecton()
	}
}
