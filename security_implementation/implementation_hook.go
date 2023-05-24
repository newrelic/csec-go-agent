// Copyright 2023 New Relic Corporation. All rights reserved.
// SPDX-License-Identifier: New Relic Pre-Release

package security_implementation

import (
	"errors"
	"os"
	"reflect"
	"runtime"
	"strconv"
	"strings"

	"github.com/k2io/hookingo"
)

type hookedMethodTuple struct {
	functionName string
	fileName     string
	lineNumber   string
}

var symbolTable map[string]uintptr
var linkMap map[uintptr]hookedMethodTuple

// HookWrap is used to apply hooks on package public function
func (k Secureimpl) HookWrap(from, to, toc interface{}) error {
	_, err := hookingo.ApplyWrap(from, to, toc)
	if err != nil {
		err = errors.New("unable to apply hook hookingo failure " + err.Error())
	} else {
		setAddrMapInterface(from, to, toc)
	}

	return err
}

// HookWrapInterface is used to apply hooks on  instance function
func (k Secureimpl) HookWrapInterface(from, to, toc interface{}) error {
	_, err := hookingo.ApplyWrapInterface(from, to, toc)
	if err != nil {
		err = errors.New("unable to apply hook hookingo failure " + err.Error())
	} else {
		setAddrMapInterface(from, to, toc)
	}
	return err
}

func (k Secureimpl) HookWrapRaw(from uintptr, to, toc interface{}) error {
	_, err := hookingo.ApplyWrapRaw(from, to, toc)
	if err != nil {
		err = errors.New("unable to apply hook hookingo failure " + err.Error())
	} else {
		setAddrMap(from, to, toc)
	}
	return err
}

// HookWrapRawNamed is used to apply hooks by function name.
// Generally this method is used to apply hooks on private function.
// With the help of the function name and symbols Table we get the function address.
func (k Secureimpl) HookWrapRawNamed(xstrfrom string, to, toc interface{}) (string, error) {
	if symbolTable == nil {
		return "", errors.New("Unable to apply hook ,symbolTable table is empty")
	}
	methodName := convertPtrReceiver(xstrfrom)
	from, ok := symbolTable[methodName]
	if !ok {
		return "", errors.New("Unable to locate and Hook for :" + xstrfrom)
	}
	_, err := hookingo.ApplyWrapRaw(from, to, toc)
	if err != nil {
		err = errors.New("Unable to apply hook hookingo failure " + err.Error())
	} else {
		setAddrMap(from, to, toc)
	}
	return xstrfrom, err
}

// Based on the running OS debug symbol was initialized
// To use this function debug symbol must be enabled
func (k Secureimpl) InitSyms() error {
	applicationBinaryPath, err := os.Executable()
	if err != nil {
		applicationBinaryPath = os.Args[0]
	}
	symTable, err := hookingo.GetSymbols(applicationBinaryPath)
	if err != nil || symTable == nil {
		return errors.New("No debug symbols Found fileName :" + applicationBinaryPath)

	} else {
		symbolTable = symTable
	}
	return nil
}

// linkMap to get original function name from the hooked function pointer
func convertPtrReceiver(s string) string {
	if strings.HasPrefix(s, "*") {
		i := strings.LastIndex(s, ".")
		if i < 0 {
			return s
		}
		j := strings.Index(s, ".")
		if j < 0 {
			return s
		}
		if i == j {
			return s
		}
		name := s[1:j] + ".(*" + s[j+1:i] + ")." + s[i+1:]
		return name
	} else {
		return s
	}
}

func linkMapLookup(u uintptr) (bool, hookedMethodTuple) {
	unkTuple := hookedMethodTuple{functionName: "unknownMethod", fileName: "unknownFile", lineNumber: "unknownLine"}
	t, ok := linkMap[u]
	if !ok {
		return false, unkTuple
	}
	return true, t
}

func setAddrMap(from uintptr, to, toc interface{}) string {

	t1 := hookedMethodTuple{functionName: "unknownMethod", fileName: "unknownFile", lineNumber: "unknownLine"}
	var name string
	f := runtime.FuncForPC(from)
	if f != nil {
		fi, li := f.FileLine(from)
		t1 = hookedMethodTuple{functionName: f.Name(), fileName: fi, lineNumber: strconv.Itoa(li)}
		name = f.Name()
	} else {
		name = "unknown"
	}
	vpc := reflect.ValueOf(to)
	pc := uintptr(vpc.Pointer())
	linkMap[pc] = t1

	vpc = reflect.ValueOf(toc)
	pc = uintptr(vpc.Pointer())
	linkMap[pc] = t1

	return name
}

func setAddrMapInterface(from, to, toc interface{}) string {
	t1 := functionId(from)

	vpc := reflect.ValueOf(to)
	pc := uintptr(vpc.Pointer())
	linkMap[pc] = t1

	vpc = reflect.ValueOf(toc)
	pc = uintptr(vpc.Pointer())
	linkMap[pc] = t1

	return t1.functionName
}

func functionId(x interface{}) hookedMethodTuple {

	vpc := reflect.ValueOf(x)
	pc := uintptr(vpc.Pointer())
	f := runtime.FuncForPC(pc)
	if f != nil {
		fi, li := f.FileLine(pc)
		return hookedMethodTuple{functionName: f.Name(), fileName: fi, lineNumber: strconv.Itoa(li)}
	}
	unkTuple := hookedMethodTuple{functionName: "unknownMethod", fileName: "unknownFile", lineNumber: "unknownLine"}
	return unkTuple
}
