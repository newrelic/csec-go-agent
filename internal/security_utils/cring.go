// Copyright 2023 New Relic Corporation. All rights reserved.
// SPDX-License-Identifier: New Relic Pre-Release

package security_utils

import (
	"sync"
)

// --------------------------------------------------
// simple circular buffer
// --------------------------------------------------

type Cring struct {
	bufferSize int
	data       []interface{}
	start, end int
	sync.Mutex
}

// size of cring buffer
func (cr *Cring) Size() int {
	return cr.bufferSize
}

// number of buffered objects
func (cr *Cring) Count() int {
	if cr.IscringEmpty() {
		return 0
	}
	if cr.IscringFull() {
		return cr.bufferSize
	}
	if cr.end > cr.start {
		return cr.end - cr.start + 1
	} else {
		return (cr.end + 1) + (cr.bufferSize - cr.start)
	}
}

func (cr *Cring) IscringFull() bool {
	return (cr.start == cr.end) && (cr.end != -1)

}

func (cr *Cring) IscringEmpty() bool {
	return (cr.end == -1)
}

// return Peek of cring
func (cr *Cring) Peek() interface{} {
	cr.Lock()
	defer cr.Unlock()
	if cr.IscringEmpty() {
		return nil
	}
	return cr.data[cr.start]
}

// remove peek object from cring
func (cr *Cring) Remove() interface{} {
	cr.Lock()
	defer cr.Unlock()

	if cr.IscringEmpty() {
		return nil
	}
	s := cr.data[cr.start]
	cr.start++
	if cr.start == cr.Size() {
		cr.start = 0
	}
	if cr.start == cr.end {
		cr.start = 0
		cr.end = -1
	}
	return s
}

// add object from cring
func (cr *Cring) Add(astr []byte) int {
	cr.Lock()
	defer cr.Unlock()
	if cr.IscringFull() {
		return -1
	}
	if cr.IscringEmpty() {
		cr.end = 0
		cr.start = 0
	}
	cr.data[cr.end] = astr
	cr.end++
	if cr.end == cr.Size() {
		cr.end = 0
	}
	return cr.end
}

// Force Insert object in cring rewrite element at start
func (cr *Cring) ForceInsert(astr string) {
	cr.Lock()
	defer cr.Unlock()
	// if cr.IscringFull() {
	// 	return
	// }
	if cr.IscringEmpty() {
		cr.end = 0
		cr.start = 0
	}
	cr.data[cr.end] = astr
	cr.end++
	if cr.end == cr.Size() {
		cr.end = 0
	}
	return
}

func (cr *Cring) Get() interface{} {
	return cr.data
}

// create new object of cring
func NewCring(size int) Cring {
	return Cring{
		size,
		make([]interface{}, size),
		0,
		-1,
		sync.Mutex{},
	}
}
