package security_intercept

import (
	"time"

	secConfig "github.com/newrelic/csec-go-agent/security_config"
	secWs "github.com/newrelic/csec-go-agent/security_handlers"
	"github.com/robfig/cron"
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
		go shutdownAtDurationReached()
	}

}

func startAgentWithDelay() {
	if secConfig.GlobalInfo.ScanScheduleAllowIastSampleCollection() {
		secWs.InitializeWsConnecton()
		go shutdownAtDurationReached()
	} else {
		logger.Debugln("Security Agent delay scan time is set to:", time.Now().Add(time.Duration(secConfig.GlobalInfo.ScanScheduleDelay())*time.Minute).Format(time.ANSIC))
		time.Sleep(time.Duration(secConfig.GlobalInfo.ScanScheduleDelay()) * time.Minute)
		secWs.InitializeWsConnecton()
		go shutdownAtDurationReached()
	}
}

func startAgentWithCronExpr(expr string) {

	isStarted := false
	if secConfig.GlobalInfo.ScanScheduleDuration() == 0 {
		nextTime := getNextTime(expr)
		logger.Debugln("Security Agent delay scan time is set via cron expr to:", nextTime.Format(time.ANSIC))
		time.Sleep(time.Until(nextTime))
		secWs.InitializeWsConnecton()
	} else {
		c := cron.New()
		c.AddFunc(expr, func() {
			if isStarted {
				if !secConfig.SecureWS.GetStatus() {
					logger.Debugln("Reconnecting agent due to cron expr")
					secConfig.SecureWS.ReconnectAtAgentRefresh()
					go shutdownAtDurationReached()
				}
			} else {
				logger.Debugln("Initialize ws connecton agent due to cron expr")
				secWs.InitializeWsConnecton()
				isStarted = true
				go shutdownAtDurationReached()
			}
		})
		c.Start()
	}
}

func shutdownAtDurationReached() {
	logger.Debugln("IAST Duration is set to: ", secConfig.GlobalInfo.ScanScheduleDuration())
	duration := secConfig.GlobalInfo.ScanScheduleDuration()
	if duration <= 0 {
		return
	}
	logger.Debugln("Security Agent Duration scan time is set to:", time.Now().Add(time.Duration(secConfig.GlobalInfo.ScanScheduleDuration())*time.Minute).Format(time.ANSIC))
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
	specParser := cron.NewParser(cron.Second | cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.DowOptional | cron.Descriptor)
	sched, err := specParser.Parse(expr)
	if err != nil {
		return time.Now()
	} else {
		return sched.Next(time.Now())
	}
}
