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
		logger.Debugln("IAST delay is set to: ", secConfig.GlobalInfo.ScanScheduleDelay(), "min")
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
	delay := secConfig.GlobalInfo.ScanScheduleDelay()

	if secConfig.GlobalInfo.ScanScheduleAllowIastSampleCollection() {
		logger.Debugln("initializing websocket connection immediately, scan schedule allow iast sample collection set true")
		secWs.InitializeWsConnecton()
		go shutdownAtDurationReached(delay)
	} else {
		dealyAgentTill := time.Duration(delay) * time.Minute
		logger.Debugln("Security Agent delay scan time is set to:", time.Now().Add(dealyAgentTill).Format(time.ANSIC))
		time.Sleep(dealyAgentTill)
		logger.Debugln("initializing websocket connection delay end")
		secWs.InitializeWsConnecton()
		go shutdownAtDurationReached(0)
	}
}

// scheduler
func startAgentWithCronExpr(expr string) {
	go cronExprTask(expr)
}

// Duration
func shutdownAtDurationReached(delta int) {
	duration := secConfig.GlobalInfo.ScanScheduleDuration()

	logger.Debugln("IAST Duration is set to: ", duration)
	if duration <= 0 {
		return
	}
	duration += delta
	logger.Debugln("Security Agent shutdown is set to:", time.Now().Add(time.Duration(duration)*time.Minute).Format(time.ANSIC))
	timeout := time.NewTimer(time.Duration(duration+delta) * time.Minute)
	<-timeout.C
	DeactivateSecurity()

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
