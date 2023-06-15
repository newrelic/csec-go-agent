// Copyright 2023 New Relic Corporation. All rights reserved.
// SPDX-License-Identifier: New Relic Pre-Release

package security_threadpool

import (
	"fmt"

	"github.com/sirupsen/logrus"
)

type Task interface {
	Run()
}

type ThreadPool struct {
	jobs        chan interface{}
	closeHandle chan bool
	logger      *logrus.Entry
	name        string
}

func NewThreadPool(queueSize int, noOfThreads int, logger *logrus.Entry, name string) *ThreadPool {
	tr := &ThreadPool{}
	tr.jobs = make(chan interface{}, queueSize)
	tr.closeHandle = make(chan bool)
	tr.logger = logger
	tr.name = name
	tr.createThreadPool(noOfThreads)
	return tr
}

func (tr *ThreadPool) RegisterTask(task interface{}) error {
	if len(tr.jobs) == cap(tr.jobs) {
		return fmt.Errorf("job queue is full, not able register the task")
	}
	tr.logger.Debugln(len(tr.jobs), cap(tr.jobs))
	tr.jobs <- task
	return nil
}

func (tr *ThreadPool) PendingTask() int {
	return len(tr.jobs)
}
func (tr *ThreadPool) IsTaskPoolEmpty() bool {
	return len(tr.jobs) == 0
}
func (tr *ThreadPool) RemainingCapacity() int {
	return cap(tr.jobs) - len(tr.jobs)
}
func (tr *ThreadPool) createThreadPool(noOfThreads int) {
	for i := 0; i < noOfThreads; i++ {
		go tr.createThread(i)
	}
}

func (tr *ThreadPool) createThread(num int) {
	tr.logger.Infoln("start thread pool Name =", tr.name, "Number = ", num)
	for {
		select {
		case task := <-tr.jobs:
			tr.executeTask(task)
		case <-tr.closeHandle:
			tr.logger.Infoln("close thread poolName =", tr.name, "Number = ", num)
			return
		}
	}
}

func (tr *ThreadPool) executeTask(task interface{}) {
	switch task := task.(type) {
	case Task:
		task.Run()
	default:
		tr.logger.Errorln("Task must me implement Run method")
	}
}
