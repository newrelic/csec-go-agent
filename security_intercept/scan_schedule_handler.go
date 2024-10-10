package security_intercept

import (
	"time"

	"github.com/adhocore/gronx"
	secConfig "github.com/newrelic/csec-go-agent/security_config"
	secWs "github.com/newrelic/csec-go-agent/security_handlers"
)

func StartWsConnection() {

	secConfig.GlobalInfo.SetDealyAgentTill(secConfig.GlobalInfo.ScanScheduleDelay())
	if secConfig.GlobalInfo.ScanScheduleDelay() > 0 {
		logger.Debugln("IAST delay is set to: ", secConfig.GlobalInfo.ScanScheduleDelay())
		startAgentWithDelay()
	} else if expr := secConfig.GlobalInfo.ScanScheduleSchedule(); expr != "" {
		logger.Debugln("IAST Cron Expr is set to: ", expr)
		startAgentWithCronExpr(expr)
	} else {
		secWs.InitializeWsConnecton()
		go shutdownAtDurationReached(0)
	}

}

func startAgentWithDelay() {
	if secConfig.GlobalInfo.ScanScheduleAllowIastSampleCollection() {
		secWs.InitializeWsConnecton()
		go shutdownAtDurationReached(secConfig.GlobalInfo.ScanScheduleDelay())
	} else {
		logger.Debugln("Security Agent delay scan time is set to:", time.Now().Add(time.Duration(secConfig.GlobalInfo.ScanScheduleDelay())*time.Minute).Format(time.ANSIC))
		time.Sleep(time.Duration(secConfig.GlobalInfo.ScanScheduleDelay()) * time.Minute)
		secWs.InitializeWsConnecton()
		go shutdownAtDurationReached(0)
	}
}

func startAgentWithCronExpr(expr string) {
	go cronExprTask(expr)
}

func shutdownAtDurationReached(delta int) {
	logger.Debugln("IAST Duration is set to: ", secConfig.GlobalInfo.ScanScheduleDuration())
	duration := secConfig.GlobalInfo.ScanScheduleDuration()
	if duration <= 0 {
		return
	}
	duration += delta
	logger.Debugln("Security Agent Duration scan time is set to:", time.Now().Add(time.Duration(duration)*time.Minute).Format(time.ANSIC))
	t := time.NewTicker(time.Duration(duration) * time.Minute)
	for {
		select {
		case <-t.C:
			DeactivateSecurity()
			t.Stop()
			return
		}
	}

}

func getNextTime(expr string) time.Time {
	nextTime, err := gronx.NextTick(expr, true)
	if err != nil {
		return time.Now()
	} else {
		return nextTime
	}
}

func cronExprTask(expr string) {
	isStarted := false
	for {
		nextTime := getNextTime(expr)
		logger.Debugln("Security Agent delay scan time is set via cron expr to:", nextTime.Format(time.ANSIC))
		time.Sleep(time.Until(nextTime))

		if isStarted {
			if !secConfig.SecureWS.GetStatus() {
				logger.Debugln("Reconnecting agent due to cron expr ")
				secConfig.SecureWS.ReconnectAtAgentRefresh()
			}
		} else {
			isStarted = true
			logger.Debugln("Initialize ws connecton agent due to cron expr")
			secWs.InitializeWsConnecton()
		}

		if secConfig.GlobalInfo.ScanScheduleDuration() == 0 {
			return
		} else {
			go shutdownAtDurationReached(0)
		}

	}
}
