package security_logs

import (
	"fmt"
	"path/filepath"
)

var initLogger = DefaultLogger(true)

func init_initLogger(initlogFileName, logFilepath string, pid int) {

	rotateFileHook, writer, err := NewRotateFileHook(RotateFileConfig{
		Filename:        filepath.Join(logFilepath, initlogFileName),
		MaxSize:         50, // megabytes
		MaxBackups:      2,
		BaseLogFilename: initlogFileName,
	})
	if err != nil {
		fmt.Println(err)
		return
	}

	UpdateLogger(writer, "INFO", pid, initLogger, rotateFileHook)
}

func InitLogger() *logFile {
	return initLogger
}

func EndStage(stageId, logs interface{}) {
	print := fmt.Sprintf("[STEP-%s] %s", stageId, logs)
	PrintInitlog(print)
}
func PrintInitlog(logs interface{}) {
	initLogger.Infoln(logs)
}

func PrintInitErrolog(logs string) {
	initLogger.Errorln(logs)
}
func PrintWarnlog(logs string) {
	initLogger.Warnln(logs)
}
func Disableinitlogs() {
	initLogger.isActive = false
}
