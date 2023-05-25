// Copyright 2023 New Relic Corporation. All rights reserved.
// SPDX-License-Identifier: New Relic Pre-Release

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
)

type RotateFileConfig struct {
	Filename        string
	BaseLogFilename string
	MaxSize         int64
	MaxBackups      int
}

type RotateFileHook struct {
	Config    RotateFileConfig
	logWriter os.File
}

func NewRotateFileHook(config RotateFileConfig) (*RotateFileHook, *os.File, error) {

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

func (hook *RotateFileHook) Fire(logMessege, mode string) string {
	re := regexp.MustCompile(`license_key=[a-fA-F0-9.]+`)
	logMessege = re.ReplaceAllLiteralString(logMessege, "license_key=[redacted]")

	if mode == "ERROR" {
		trackError(logMessege)
	}

	info, err := os.Stat(hook.Config.Filename)
	if err == nil && info.Size() > hook.Config.MaxSize*1024*1024 {
		hook.logrollover()
	}
	return logMessege
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
