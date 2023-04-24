// Copyright 2022 New Relic Corporation. All rights reserved.

package security_logs

import (
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/juju/fslock"
	"github.com/sirupsen/logrus"
)

type RotateFileConfig struct {
	Filename        string
	BaseLogFilename string
	MaxSize         int64
	MaxBackups      int
	Level           logrus.Level
}

type RotateFileHook struct {
	Config    RotateFileConfig
	logWriter os.File
}

func NewRotateFileHook(config RotateFileConfig) (logrus.Hook, *os.File, error) {

	logfile, err := os.OpenFile(config.Filename, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0777)

	if err != nil {
		return nil, nil, err
	}

	hook := RotateFileHook{
		Config:    config,
		logWriter: *logfile,
	}

	return &hook, logfile, nil
}

func (hook *RotateFileHook) Levels() []logrus.Level {
	return logrus.AllLevels[:hook.Config.Level+1]
}

func (hook *RotateFileHook) Fire(entry *logrus.Entry) (err error) {
	re := regexp.MustCompile(`license_key=[a-fA-F0-9.]+`)
	sanitized := re.ReplaceAllLiteralString(entry.Message, "license_key=[redacted]")
	entry.Message = sanitized
	if entry.Level == logrus.ErrorLevel {
		trackError(entry.Message)
	}

	info, err := os.Stat(hook.Config.Filename)
	if err == nil && info.Size() > hook.Config.MaxSize*1024*1024 {
		err := hook.logrollover()
		if err != nil {
			return err
		}
		return nil
	}
	return nil
}

func (hook *RotateFileHook) logrollover() error {

	lock := fslock.New(hook.Config.Filename)
	lockErr := lock.TryLock()
	if lockErr != nil {
		//some other process has a lock on the log file so no need to rollover this
		return nil
	}

	logFile, err := os.Open(hook.Config.Filename)

	if err != nil {
		return err
	}

	timeStamp := time.Now().Unix()
	rolloverLogFile, err := os.OpenFile(hook.Config.Filename+"."+strconv.FormatInt(timeStamp, 10), os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0777)
	if err != nil {
		return err
	}
	defer logFile.Close()
	defer rolloverLogFile.Close()

	_, err = io.Copy(rolloverLogFile, logFile)
	if err != nil {
		return err
	}
	err = os.Truncate(hook.Config.Filename, 0)

	if err != nil {
		return err
	}
	err = lock.Unlock()
	if err != nil {
		return err
	}
	return hook.DeleteFileIdNeeded(hook.Config.BaseLogFilename, filepath.Dir(hook.Config.Filename))

}

func (hook *RotateFileHook) DeleteFileIdNeeded(filename, dirpath string) error {
	files, err := ioutil.ReadDir(dirpath)
	if err != nil {
		return err
	}
	var dir = []string{}
	for _, file := range files {
		if strings.Contains(file.Name(), filename+".") {
			dir = append(dir, file.Name())
		}
	}
	if len(dir) > hook.Config.MaxBackups {
		err := os.Remove(filepath.Join(dirpath, dir[0]))
		if err != nil {
			return err
		}
	}
	return nil
}
