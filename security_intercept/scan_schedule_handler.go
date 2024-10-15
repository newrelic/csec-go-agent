package security_intercept

import (
	"time"

	"github.com/adhocore/gronx"
	secConfig "github.com/newrelic/csec-go-agent/security_config"
	secWs "github.com/newrelic/csec-go-agent/security_handlers"
)

var durationTimer *time.Timer

func StartWsConnection() {

	agentDelay := secConfig.GlobalInfo.ScanScheduleDelay()
	duration := secConfig.GlobalInfo.ScanScheduleDuration()
	schedule := secConfig.GlobalInfo.ScanScheduleSchedule()

	logger.Debugln("IAST delay is set to: ", agentDelay, "min")
	logger.Debugln("IAST duration is set to: ", duration, "min")
	logger.Debugln("IAST schedule cron expression is set to: ", schedule)

	if agentDelay > 0 {
		startAgentWithDelay(time.Duration(agentDelay) * time.Minute)
	} else if schedule != "" {
		cronExprTask(schedule, duration)
	} else {
		connect()
		InitFuzzScheduler()
	}
}

func startAgentWithDelay(delay time.Duration) {

	if secConfig.GlobalInfo.ScanScheduleAllowIastSampleCollection() {
		logger.Debugln("initializing websocket connection immediately, scan schedule allow iast sample collection set true")
		connect()
	}

	logger.Debugln("Security Agent delay scan time is set to:", time.Now().UTC().Add(delay).Format(time.ANSIC))
	time.Sleep(delay)
	connect()
	InitFuzzScheduler()

}

// Duration
func shutdownAtDurationReached() {
	<-durationTimer.C
	durationTimer = nil
	logger.Debugln("Security Agent shutdown duration reached")
	secWs.CloseFuzzScheduler()
	if !secConfig.GlobalInfo.ScanScheduleAllowIastSampleCollection() {
		DeactivateSecurity()
	}
}

func getNextTime(expr string) (time.Time, error) {
	nextTime, err := gronx.NextTick(expr, true)
	if err != nil {
		logger.Errorln("Invalid cron expr", err)
		return time.Now(), err
	} else {
		return nextTime, nil
	}
}

func cronExprTask(expr string, duration int) {
	for {
		nextTime, err := getNextTime(expr)
		startAgentWithDelay(nextTime.Sub(time.Now()))
		if duration <= 0 || err != nil {
			return
		}
		time.Sleep(2 * time.Second)
	}
}

func connect() {
	if secConfig.SecureWS == nil {
		secWs.InitializeWsConnecton()
	} else if !secConfig.SecureWS.GetStatus() {
		secConfig.SecureWS.ReconnectAtAgentRefresh()
	}
}

func InitFuzzScheduler() {
	secWs.FuzzHandler.InitFuzzScheduler()
	duration := secConfig.GlobalInfo.ScanScheduleDuration()
	if duration != 0 {
		if durationTimer == nil {
			logger.Debugln("Security Agent shutdown is set to:", time.Now().UTC().Add(time.Duration(duration)*time.Minute).Format(time.ANSIC))
			durationTimer = time.NewTimer(time.Duration(duration) * time.Minute)
			go shutdownAtDurationReached()
		}
	}
}
