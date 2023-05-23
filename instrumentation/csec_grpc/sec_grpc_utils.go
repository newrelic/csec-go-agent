// Copyright 2023 New Relic Corporation. All rights reserved.
// SPDX-License-Identifier: New Relic Pre-Release

package csec_grpc

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"path/filepath"

	grpccurl "github.com/fullstorydev/grpcurl"
	secConfig "github.com/newrelic/csec-go-agent/security_config"
	secIntercept "github.com/newrelic/csec-go-agent/security_intercept"
)

var confFile = ""

const confFileName = "/csec_grpc_conf.json"

var confFilePath = ""

var confImportPaths []string
var confImportFiles []string

// ---- GRPC Conf -----

type GrpcConf struct {
	ImportPaths []string `json:"importPaths"`
	ImportFiles []string `json:"importedFiles"`
}

func checkAndCreateconfFile() error {
	logger.Debugln("Creating Grpc Config file")
	deployedPath, e := filepath.Abs(secConfig.GlobalInfo.ApplicationInfo.Cmd)
	if e != nil {
		deployedPath = secConfig.GlobalInfo.ApplicationInfo.Cmd
	}
	deployedPath = filepath.Dir(deployedPath)
	confFile = deployedPath + confFileName
	confFilePath = confFile
	if secIntercept.IsFileExist(confFile) {
		plan, err := ioutil.ReadFile(confFile)
		if err != nil {
			return err
		}
		var conf GrpcConf
		err = json.Unmarshal(plan, &conf)
		if err != nil {
			return err
		}
		confImportPaths = conf.ImportPaths
		confImportFiles = conf.ImportFiles
		return nil
	}

	var importPaths []string
	var importFiles []string

	err := filepath.Walk(deployedPath, func(path string, info os.FileInfo, err error) error {
		if info.IsDir() {
			return nil
		}
		if filepath.Ext(path) == ".proto" {
			abs, err := filepath.Abs(path)
			if err == nil {
				importPaths = append(importPaths, filepath.Dir(abs))
				importFiles = append(importFiles, filepath.Base(abs))
			}
		}
		return nil
	})
	if err != nil {
		logger.Errorln("Error during Creating Grpc Conf file")
	}
	if len(importPaths) > 0 && len(importFiles) > 0 {
		_, refSourceErr := grpccurl.DescriptorSourceFromProtoFiles(importPaths, importFiles...)
		if refSourceErr != nil {
			importPaths = importPaths[:0]
			importFiles = importFiles[:0]
		}
	}
	var conf GrpcConf

	if len(importPaths) == 0 && len(importFiles) == 0 {
		importPaths = append(importPaths, "")
		importFiles = append(importFiles, "")
	}
	conf.ImportPaths = importPaths
	conf.ImportFiles = importFiles
	file, err := json.MarshalIndent(conf, "", " ")
	if err == nil {
		err = ioutil.WriteFile(confFile, file, 0644)
		confImportPaths = conf.ImportPaths
		confImportFiles = conf.ImportFiles
	}
	if err != nil {
		return err
	} else {
		return nil
	}
}
