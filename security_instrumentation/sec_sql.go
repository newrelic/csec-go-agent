// Copyright 2023 New Relic Corporation. All rights reserved.
// SPDX-License-Identifier: New Relic Pre-Release

package security_instrumentation

import (
	"context"
	"database/sql"
	"fmt"

	logging "github.com/newrelic/csec-go-agent/internal/security_logs"
	secIntercept "github.com/newrelic/csec-go-agent/security_intercept"
)

type SecDB struct {
	sql.DB
}

//go:noinline
func (k *SecDB) secQueryContext_s(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error) {
	if secIntercept.IsDisable() {
		return k.secQueryContext_s(ctx, query, args...)
	}
	logger.Debugln("Hook Called : ", "(*sql.DB).QueryContext")
	eventId := secIntercept.TraceSqlOperation(query, args...)
	row, err := k.secQueryContext_s(ctx, query, args...)
	secIntercept.SendExitEvent(eventId, err)
	return row, err
}

//go:noinline
func (k *SecDB) secQueryContext(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error) {
	if secIntercept.IsDisable() {
		return k.secQueryContext_s(ctx, query, args...)
	}
	logger.Debugln("Hook Called : ", "(*sql.DB).QueryContext")
	eventId := secIntercept.TraceSqlOperation(query, args...)
	row, err := k.secQueryContext_s(ctx, query, args...)
	secIntercept.SendExitEvent(eventId, err)
	return row, err
}

//go:noinline
func (k *SecDB) secExecContext_s(ctx context.Context, query string, args ...interface{}) (sql.Result, error) {
	if secIntercept.IsDisable() {
		return k.secExecContext_s(ctx, query, args...)
	}
	logger.Debugln("Hook Called : ", "(*sql.DB).ExecContext")
	eventId := secIntercept.TraceSqlOperation(query, args...)
	result, err := k.secExecContext_s(ctx, query, args...)
	secIntercept.SendExitEvent(eventId, err)
	return result, err
}

//go:noinline
func (k *SecDB) secExecContext(ctx context.Context, query string, args ...interface{}) (sql.Result, error) {
	if secIntercept.IsDisable() {
		return k.secExecContext_s(ctx, query, args...)
	}
	logger.Debugln("Hook Called : ", "(*sql.DB).ExecContext")
	eventId := secIntercept.TraceSqlOperation(query, args...)
	result, err := k.secExecContext_s(ctx, query, args...)
	secIntercept.SendExitEvent(eventId, err)
	return result, err
}

//go:noinline
func (k *SecDB) secPrepareContext_s(ctx context.Context, query string) (*sql.Stmt, error) {
	if secIntercept.IsDisable() {
		return k.secPrepareContext_s(ctx, query)
	}
	logger.Debugln("Hook Called : ", "(*sql.DB).PrepareContext")
	stmt, err := k.secPrepareContext_s(ctx, query)
	if stmt != nil {
		myString := fmt.Sprintf("%p", stmt)
		secIntercept.TracePrepareStatement(query, myString)
	}
	return stmt, err
}

//go:noinline
func (k *SecDB) secPrepareContext(ctx context.Context, query string) (*sql.Stmt, error) {
	if secIntercept.IsDisable() {
		return k.secPrepareContext_s(ctx, query)
	}
	logger.Debugln("Hook Called : ", "(*sql.DB).PrepareContext")
	stmt, err := k.secPrepareContext_s(ctx, query)
	if stmt != nil {
		myString := fmt.Sprintf("%p", stmt)
		secIntercept.TracePrepareStatement(query, myString)
	}
	return stmt, err
}

type SecConn struct {
	sql.Conn
}

//go:noinline
func (k *SecConn) secQueryContext_s(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error) {
	if secIntercept.IsDisable() {
		return k.secQueryContext_s(ctx, query, args...)
	}
	logger.Debugln("Hook Called : ", "(*sql.Conn).QueryContext")
	eventId := secIntercept.TraceSqlOperation(query, args...)
	rows, err := k.secQueryContext_s(ctx, query, args...)
	secIntercept.SendExitEvent(eventId, err)
	return rows, err
}

//go:noinline
func (k *SecConn) secQueryContext(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error) {
	if secIntercept.IsDisable() {
		return k.secQueryContext_s(ctx, query, args...)
	}
	logger.Debugln("Hook Called : ", "(*sql.Conn).QueryContext")
	eventId := secIntercept.TraceSqlOperation(query, args...)
	rows, err := k.secQueryContext_s(ctx, query, args...)
	secIntercept.SendExitEvent(eventId, err)
	return rows, err
}

//go:noinline
func (k *SecConn) secExecContext_s(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error) {
	if secIntercept.IsDisable() {
		return k.secExecContext_s(ctx, query, args...)
	}
	logger.Debugln("Hook Called : ", "(*sql.Conn).ExecContext")
	eventId := secIntercept.TraceSqlOperation(query, args...)
	rows, err := k.secExecContext_s(ctx, query, args...)
	secIntercept.SendExitEvent(eventId, err)
	return rows, err
}

//go:noinline
func (k *SecConn) secExecContext(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error) {
	if secIntercept.IsDisable() {
		return k.secExecContext_s(ctx, query, args...)
	}
	logger.Debugln("Hook Called : ", "(*sql.Conn).ExecContext")
	eventId := secIntercept.TraceSqlOperation(query, args...)
	rows, err := k.secExecContext_s(ctx, query, args...)
	secIntercept.SendExitEvent(eventId, err)
	return rows, err
}

//go:noinline
func (k *SecConn) secPrepareContext_s(ctx context.Context, query string) (*sql.Stmt, error) {
	if secIntercept.IsDisable() {
		return k.secPrepareContext_s(ctx, query)
	}
	logger.Debugln("Hook Called : ", "(*sql.Conn).PrepareContext")
	stmt, err := k.secPrepareContext_s(ctx, query)
	if stmt != nil {
		address := fmt.Sprintf("%p", stmt)
		secIntercept.TracePrepareStatement(query, address)
	}
	return stmt, err
}

//go:noinline
func (k *SecConn) secPrepareContext(ctx context.Context, query string) (*sql.Stmt, error) {
	if secIntercept.IsDisable() {
		return k.secPrepareContext_s(ctx, query)
	}
	logger.Debugln("Hook Called : ", "(*sql.Conn).PrepareContext")
	stmt, err := k.secPrepareContext_s(ctx, query)
	if stmt != nil {
		address := fmt.Sprintf("%p", stmt)
		secIntercept.TracePrepareStatement(query, address)
	}
	return stmt, err
}

type SecTx struct {
	sql.Tx
}

//go:noinline
func (k *SecTx) secQueryContext_s(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error) {
	if secIntercept.IsDisable() {
		return k.secQueryContext_s(ctx, query, args...)
	}
	logger.Debugln("Hook Called : ", "(*sql.SecTx).QueryContext")
	eventId := secIntercept.TraceSqlOperation(query, args...)
	rows, err := k.secQueryContext_s(ctx, query, args...)
	secIntercept.SendExitEvent(eventId, err)
	return rows, err
}

//go:noinline
func (k *SecTx) secQueryContext(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error) {
	if secIntercept.IsDisable() {
		return k.secQueryContext_s(ctx, query, args...)
	}
	logger.Debugln("Hook Called : ", "(*sql.SecTx).QueryContext")
	eventId := secIntercept.TraceSqlOperation(query, args...)
	rows, err := k.secQueryContext_s(ctx, query, args...)
	secIntercept.SendExitEvent(eventId, err)
	return rows, err
}

//go:noinline
func (k *SecTx) secExecContext_s(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error) {
	if secIntercept.IsDisable() {
		return k.secExecContext_s(ctx, query, args...)
	}
	logger.Debugln("Hook Called : ", "(*sql.SecTx).ExecContext")
	eventId := secIntercept.TraceSqlOperation(query, args...)
	rows, err := k.secExecContext_s(ctx, query, args...)
	secIntercept.SendExitEvent(eventId, err)
	return rows, err
}

//go:noinline
func (k *SecTx) secExecContext(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error) {
	if secIntercept.IsDisable() {
		return k.secExecContext_s(ctx, query, args...)
	}
	logger.Debugln("Hook Called : ", "(*sql.SecTx).ExecContext")
	eventId := secIntercept.TraceSqlOperation(query, args...)
	rows, err := k.secExecContext_s(ctx, query, args...)
	secIntercept.SendExitEvent(eventId, err)
	return rows, err
}

//go:noinline
func (k *SecTx) secPrepareContext_s(ctx context.Context, query string) (*sql.Stmt, error) {
	if secIntercept.IsDisable() {
		return k.secPrepareContext_s(ctx, query)
	}
	logger.Debugln("Hook Called : ", "(*sql.SecTx).PrepareContext_s")
	stmt, err := k.secPrepareContext_s(ctx, query)
	if stmt != nil {
		address := fmt.Sprintf("%p", stmt)
		secIntercept.TracePrepareStatement(query, address)
	}
	return stmt, err
}

//go:noinline
func (k *SecTx) secPrepareContext(ctx context.Context, query string) (*sql.Stmt, error) {
	if secIntercept.IsDisable() {
		return k.secPrepareContext_s(ctx, query)
	}
	logger.Debugln("Hook Called : ", "(*sql.SecTx).PrepareContext_s")
	stmt, err := k.secPrepareContext_s(ctx, query)
	if stmt != nil {
		address := fmt.Sprintf("%p", stmt)
		secIntercept.TracePrepareStatement(query, address)
	}
	return stmt, err
}

type SecStmt struct {
	sql.Stmt
}

//go:noinline
func (k *SecStmt) secExecContext_s(ctx context.Context, args ...interface{}) (*sql.Rows, error) {
	if secIntercept.IsDisable() {
		return k.secExecContext_s(ctx, args...)
	}

	logger.Debugln("in Secquery Stmt ExecContext hook")
	myAddress := fmt.Sprintf("%p", k)
	eventId := secIntercept.TraceExecPrepareStatement(myAddress, args...)
	rows, err := k.secExecContext_s(ctx, args...)
	secIntercept.SendExitEvent(eventId, err)
	return rows, err
}

//go:noinline
func (k *SecStmt) secExecContext(ctx context.Context, args ...interface{}) (*sql.Rows, error) {
	if secIntercept.IsDisable() {
		return k.secExecContext_s(ctx, args...)
	}

	logger.Debugln("in Secquery Stmt ExecContext hook")
	myAddress := fmt.Sprintf("%p", k)
	eventId := secIntercept.TraceExecPrepareStatement(myAddress, args...)
	rows, err := k.secExecContext_s(ctx, args...)
	secIntercept.SendExitEvent(eventId, err)
	return rows, err
}

//go:noinline
func (k *SecStmt) secQueryContext_s(ctx context.Context, args ...interface{}) (*sql.Rows, error) {
	if secIntercept.IsDisable() {
		return k.secQueryContext_s(ctx, args...)
	}
	logger.Debugln("Hook Called : ", "(*sql.SecTx).QueryContext")
	myAddress := fmt.Sprintf("%p", k)
	eventId := secIntercept.TraceExecPrepareStatement(myAddress, args...)
	rows, err := k.secQueryContext_s(ctx, args...)
	secIntercept.SendExitEvent(eventId, err)
	return rows, err
}

//go:noinline
func (k *SecStmt) secQueryContext(ctx context.Context, args ...interface{}) (*sql.Rows, error) {
	if secIntercept.IsDisable() {
		return k.secQueryContext_s(ctx, args...)
	}
	logger.Debugln("Hook Called : ", "(*sql.SecTx).QueryContext")
	myAddress := fmt.Sprintf("%p", k)
	eventId := secIntercept.TraceExecPrepareStatement(myAddress, args...)
	rows, err := k.secQueryContext_s(ctx, args...)
	secIntercept.SendExitEvent(eventId, err)
	return rows, err
}

var traceSqlHook error

func traceSqlHookError(name string, e error) {
	logging.IsHooked(name, e)
	if e != nil {
		traceSqlHook = e
	}
}

func initSqlHook() {

	e := secIntercept.HookWrapInterface((*sql.DB).ExecContext, (*SecDB).secExecContext, (*SecDB).secExecContext_s)
	traceSqlHookError("(*sql.DB).ExecContext", e)
	e = secIntercept.HookWrapInterface((*sql.DB).QueryContext, (*SecDB).secQueryContext, (*SecDB).secQueryContext_s)
	traceSqlHookError("(*sql.DB).QueryContext", e)
	e = secIntercept.HookWrapInterface((*sql.DB).PrepareContext, (*SecDB).secPrepareContext, (*SecDB).secPrepareContext_s)
	traceSqlHookError("(*sql.DB).PrepareContext", e)

	e = secIntercept.HookWrapInterface((*sql.Conn).QueryContext, (*SecConn).secQueryContext, (*SecConn).secQueryContext_s)
	traceSqlHookError("(*sql.Conn).QueryContext", e)
	e = secIntercept.HookWrapInterface((*sql.Conn).PrepareContext, (*SecConn).secPrepareContext, (*SecConn).secPrepareContext_s)
	traceSqlHookError("(*sql.Conn).PrepareContext", e)
	e = secIntercept.HookWrapInterface((*sql.Conn).ExecContext, (*SecConn).secExecContext, (*SecConn).secExecContext_s)
	traceSqlHookError("(*sql.Conn).ExecContext", e)

	e = secIntercept.HookWrapInterface((*sql.Tx).QueryContext, (*SecTx).secQueryContext, (*SecTx).secQueryContext_s)
	traceSqlHookError("(*sql.Tx).QueryContext", e)
	e = secIntercept.HookWrapInterface((*sql.Tx).PrepareContext, (*SecTx).secPrepareContext, (*SecTx).secPrepareContext_s)
	traceSqlHookError("(*sql.Tx).PrepareContext", e)
	e = secIntercept.HookWrapInterface((*sql.Tx).ExecContext, (*SecTx).secExecContext, (*SecTx).secExecContext_s)
	traceSqlHookError("(*sql.Tx).ExecContext", e)

	e = secIntercept.HookWrapInterface((*sql.Stmt).ExecContext, (*SecStmt).secExecContext, (*SecStmt).secExecContext_s)
	traceSqlHookError("(*sql.Stmt).ExecContext", e)
	e = secIntercept.HookWrapInterface((*sql.Stmt).QueryContext, (*SecStmt).secQueryContext, (*SecStmt).secQueryContext_s)
	traceSqlHookError("(*sql.Stmt).QueryContext", e)
	secIntercept.TraceSqlHooks(traceSqlHook)

}
