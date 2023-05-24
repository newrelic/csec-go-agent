// Copyright 2023 New Relic Corporation. All rights reserved.
// SPDX-License-Identifier: New Relic Pre-Release

package security_utils

import (
	"bufio"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
)

/*
Constants for detect environment
*/
const (
	DOCKER_STR    = "docker/"
	ECS_DIR       = "ecs/"
	KUBEPODS_DIR  = "kubepods/"
	LXC_DIR       = "lxc/" // for older versions of docker
	DIR_SEPERATOR = "/"
	DOCKER_1_13   = "/docker-" //for docker 1.13.1 version
	SCOPE         = ".scope"
	CGROUP        = "/proc/self/cgroup"
	NAMESPACE     = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
)

// structure to unmarshal ecs response josn
type EcsData struct {
	DockerID   string `json:"DockerId"`
	Name       string `json:"Name"`
	DockerName string `json:"DockerName"`
	Image      string `json:"Image"`
	ImageID    string `json:"ImageID"`
	Labels     struct {
		ComAmazonawsEcsCluster               string `json:"com.amazonaws.ecs.cluster"`
		ComAmazonawsEcsContainerName         string `json:"com.amazonaws.ecs.container-name"`
		ComAmazonawsEcsTaskArn               string `json:"com.amazonaws.ecs.task-arn"`
		ComAmazonawsEcsTaskDefinitionFamily  string `json:"com.amazonaws.ecs.task-definition-family"`
		ComAmazonawsEcsTaskDefinitionVersion string `json:"com.amazonaws.ecs.task-definition-version"`
	} `json:"Labels"`
	DesiredStatus string `json:"DesiredStatus"`
	KnownStatus   string `json:"KnownStatus"`
	Limits        struct {
		CPU int `json:"CPU"`
	} `json:"Limits"`
	CreatedAt time.Time `json:"CreatedAt"`
	StartedAt time.Time `json:"StartedAt"`
	Type      string    `json:"Type"`
	Networks  []struct {
		NetworkMode   string   `json:"NetworkMode"`
		IPv4Addresses []string `json:"IPv4Addresses"`
	} `json:"Networks"`
}

// ---------------------------------------------------
// DevOps Environment utils
// ---------------------------------------------------

func IsKubernetes() bool {
	env := os.Getenv("KUBERNETES_SERVICE_HOST")
	return env != ""
}

func IsECS() bool {
	env := os.Getenv("AWS_EXECUTION_ENV")
	return env == "AWS_ECS_FARGATE"
}
func GetKubernetesNS() string {

	data, e := ioutil.ReadFile(NAMESPACE)
	if e != nil {
		return ""
	}
	return string(data)
}

func GetPodId() string {
	file, e := os.Open(CGROUP)
	if e != nil {
		return ""
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		text := scanner.Text()
		counter := strings.LastIndex(text, KUBEPODS_DIR)
		if counter >= 0 {
			lines := strings.Split(text, "/")
			if len(lines) > 2 {
				id := lines[len(lines)-2]
				return id
			}
		}
		counter = strings.Index(text, "kubepods.slice/")
		if counter > -1 {
			counter1 := strings.Index(text, "kubepods-besteffort-pod")
			counter2 := strings.Index(text, "slice")
			if counter1 > -1 && counter2 > -1 {
				return text[counter1:counter2]
			}
		}

	}
	return ""
}

func GetContainerId() (bool, string, error) {
	file, e := os.Open(CGROUP)
	if e == nil {
		defer file.Close()
		scanner := bufio.NewScanner(file)
		scanner.Split(bufio.ScanLines)
		for scanner.Scan() {
			text := scanner.Text()
			counter := strings.LastIndex(text, DOCKER_STR)
			if counter >= 0 {
				id := text[counter+len(DOCKER_STR):]
				return true, id, nil
			}
			counter = strings.LastIndex(text, ECS_DIR)
			if counter >= 0 {
				id := text[strings.LastIndex(text, DIR_SEPERATOR)+len(DIR_SEPERATOR):]
				return true, id, nil
			}
			counter = strings.LastIndex(text, KUBEPODS_DIR)
			if counter >= 0 {
				id := text[strings.LastIndex(text, DIR_SEPERATOR)+len(DIR_SEPERATOR):]
				return true, id, nil
			}
			counter = strings.LastIndex(text, LXC_DIR)
			if counter >= 0 {
				id := text[counter+len(LXC_DIR):]
				return true, id, nil
			}
			counter = strings.LastIndex(text, DOCKER_1_13)
			counter_end := strings.LastIndex(text, SCOPE)
			if counter >= 0 && counter_end >= 0 {
				id := text[counter+len(DOCKER_1_13) : counter_end]
				return true, id, nil
			}
		}
	}
	file.Close()
	file, e = os.Open("/proc/self/mountinfo")
	if e == nil {
		defer file.Close()
		scanner := bufio.NewScanner(file)
		scanner.Split(bufio.ScanLines)
		for scanner.Scan() {
			text := scanner.Text()
			if strings.Contains(text, "/docker/containers/") {
				dummyString := strings.Split(text, "/docker/containers/")
				if len(dummyString) >= 1 {
					dummyString = strings.Split(dummyString[1], "/")
				}
				if len(dummyString) > 0 {
					id := dummyString[0]
					return true, id, nil
				}
			}
		}
		file.Close()
	}
	return false, "", nil
}

func IntToString(input int) string {
	return strconv.Itoa(input)
}

func Int64ToString(input int64) string {
	return strconv.FormatInt(input, 10)
}

func GetEcsTaskId() string {
	file, e := os.Open(CGROUP)
	if e != nil {
		return ""
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		text := scanner.Text()
		counter := strings.LastIndex(text, ECS_DIR)
		if counter >= 0 {
			id := text[counter+4 : strings.LastIndex(text, DIR_SEPERATOR)]
			return id
		}

	}
	return ""
}
func GetECSInfo() (err error, ecsData EcsData) {
	restclient := &http.Client{Timeout: 0}
	url := os.Getenv("ECS_CONTAINER_METADATA_URI")
	request, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return
	}
	response, err := restclient.Do(request)
	if err != nil {
		return
	}
	defer response.Body.Close()
	bodyBytes, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return
	}
	if response.StatusCode == 200 {
		err = json.Unmarshal(bodyBytes, &ecsData)
		return
	} else {
		return
	}

}

func GetCurrentGoVersion() int {
	current_version := runtime.Version()
	sa := strings.Split(current_version, ".")
	if len(sa) >= 1 {
		major, err := strconv.Atoi(sa[1])
		if err == nil {
			return major
		}
	}
	return 15
}
