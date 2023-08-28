// Copyright 2023 New Relic Corporation. All rights reserved.
// SPDX-License-Identifier: New Relic Pre-Release

package security_logs

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	secUtils "github.com/newrelic/csec-go-agent/internal/security_utils"
)

type RotateFileConfig struct {
	Filename        string
	Filepath        string
	BaseLogFilename string
	MaxSize         int64
	MaxBackups      int
}

type RotateFileHook struct {
	Config RotateFileConfig
	rotate sync.Mutex
}

func (config *RotateFileConfig) createLogDir() (io.Writer, error) {
	err := os.MkdirAll(config.Filepath, os.ModePerm)

	if err != nil {
		return nil, err
	}

	err = os.Chmod(config.Filepath, 0777)
	if err != nil {
		return nil, err
	}

	err = os.Chmod(filepath.Dir(config.Filepath), 0777)
	if err != nil {
		return nil, err
	}

	logfile, err := os.OpenFile(config.Filename, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0777)

	if err != nil {
		return nil, err
	}
	return logfile, nil

}

func NewRotateFileHook(config RotateFileConfig) (*RotateFileHook, io.Writer, bool) {
	logfile, err := config.createLogDir()
	idDefault := false
	if err != nil {
		fmt.Println(err)
		logfile = os.Stdout
		idDefault = true
	}

	hook := RotateFileHook{
		Config: config,
	}

	return &hook, logfile, idDefault
}

func (hook *RotateFileHook) Fire(logMessege, mode string, isDefault bool) string {
	re := regexp.MustCompile(`license_key=[a-fA-F0-9.]+`)
	logMessege = re.ReplaceAllLiteralString(logMessege, "license_key=[redacted]")

	if mode == "ERROR" {
		trackError(logMessege)
	}

	if !isDefault {
		info, err := os.Stat(hook.Config.Filename)
		if err == nil && info.Size() > hook.Config.MaxSize*1024*1024 {
			hook.logrollover()
		}
	}
	return logMessege
}

func (hook *RotateFileHook) logrollover() error {

	if !hook.rotate.TryLock() {
		return nil
	} else {
		defer hook.rotate.Unlock()
	}

	lockFile := hook.Config.Filename + ".lock"
	pid := secUtils.IntToString(os.Getpid())

	if !secUtils.IsFileExist(lockFile) {
		err := os.WriteFile(lockFile, []byte(pid), 777)
		if err != nil {
			return err
		}
	}
	lockPid, err := os.ReadFile(lockFile)
	if err == nil && string(lockPid) == pid {
		err := hook.filerollover()
		os.Remove(lockFile)
		return err
	} else if err == nil && string(lockPid) != pid {
		info, err := os.Stat(lockFile)
		if err != nil {
			return err
		}
		difference := time.Now().Sub(info.ModTime())
		if difference.Minutes() > 10 {
			os.Remove(lockFile)
		}
	}
	return err
}

func (hook *RotateFileHook) filerollover() error {
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
	if len(dir) > hook.Config.MaxBackups+1 {
		err := os.Remove(filepath.Join(dirpath, dir[0]))
		if err != nil {
			return err
		}
	}
	return nil
}
