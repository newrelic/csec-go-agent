package security_handlers

import (
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"

	secConfig "github.com/newrelic/csec-go-agent/security_config"
)

var (
	filesToRemove      []string
	filesToRemoveMutex sync.Mutex
)

func GetFilesToRemove() []string {
	filesToRemoveMutex.Lock()
	defer filesToRemoveMutex.Unlock()
	return filesToRemove
}

func SetFilesToRemove(fileName string) {
	filesToRemoveMutex.Lock()
	defer filesToRemoveMutex.Unlock()
	filesToRemove = append(filesToRemove, fileName)
}

func InitFilesClenup() {
	if !secConfig.GlobalInfo.IsIASTEnable() {
		return
	}
	t := time.NewTicker(2 * time.Minute)
	logger.Debugln("Initiating temp file & directory cleanup")
	for {
		select {
		case <-t.C:
			logger.Debugln("File cleaner invoked...")
			cleanTempDir()
			fileToRemove := GetFilesToRemove()
			if len(fileToRemove) == 0 {
				return
			} else {
				for i := len(fileToRemove) - 1; i >= 0; i-- {
					if !secureCheck(fileToRemove[i]) {
						return
					}
					modTime := getLastModifiedTime(fileToRemove[i])
					duration := time.Since(modTime)
					if duration.Minutes() > 2 {
						err := os.RemoveAll(fileToRemove[i])
						if err != nil {
							logger.Debugln("Error while removing created file : ", err.Error(), fileToRemove[i])
						}
					}
				}
			}

		}
	}
}

func cleanTempDir() {
	logger.Debugln("cleaning temp dir")
	dsFilePath := filepath.Join(secConfig.GlobalInfo.SecurityHomePath(), "nr-security-home", "tmp")
	err := filepath.Walk(dsFilePath, func(filePath string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			modTime := info.ModTime()
			duration := time.Since(modTime)
			if duration.Minutes() > 2 {
				logger.Debugln("Removing temp file & directory cleanup", filePath)
				err := os.Remove(filePath)
				if err != nil {
					return err
				}
			}
		}
		return nil
	})
	if err != nil {
		logger.Debugln("cleaning temp dir ", err.Error())
	}

}

func getLastModifiedTime(path string) time.Time {
	info, err := os.Stat(path)
	if err != nil {
		return time.Time{}
	}
	return info.ModTime()
}
func secureCheck(path string) bool {
	dsFilePath := filepath.Join(secConfig.GlobalInfo.SecurityHomePath(), "nr-security-home", "tmp")
	if path == "/" || path == "/root" || path == dsFilePath {
		return false
	}
	return true
}
