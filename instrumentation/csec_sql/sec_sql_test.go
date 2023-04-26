// Copyright 2023 New Relic Corporation. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package csec_sql

import (
	"context"
	"database/sql"
	"log"
	"testing"

	secConfig "github.com/newrelic/csec-go-agent/security_config"
	_ "github.com/newrelic/csec-go-agent/security_instrumentation"

	_ "github.com/mattn/go-sqlite3"
)

func TestSQLDbHook(t *testing.T) {

	secConfig.RegisterListener()

	db, err := sql.Open("sqlite3", "./sec_test.db")
	if err != nil {
		t.Error(err)
	}
	defer db.Close()
	statement, err :=
		db.Prepare("CREATE TABLE IF NOT EXISTS USER (id INTEGER, name TEXT)")
	if err != nil {
		t.Error(err)
	}
	statement.Exec()
	defer statement.Close()

	db.Exec("insert into USER values(2,'k2user')")

	_, err = db.Query("SELECT * FROM USER WHERE name = '" + "k2user" + "'")
	if err != nil {
		t.Error(err)
	}

	statement2, err := db.Prepare("SELECT * FROM USER WHERE id = 2")
	if err != nil {
		t.Error(err)
	}
	_, err = statement2.Query()
	if err != nil {
		t.Error(err)
	}
	defer statement2.Close()

	var expectedData = []secConfig.TestArgs{
		{Parameters: "[map[parameters:map[] query:CREATE TABLE IF NOT EXISTS USER (id INTEGER, name TEXT)]]", CaseType: secConfig.SQL},
		{Parameters: "[map[parameters:map[] query:insert into USER values(2,'k2user')]]", CaseType: secConfig.SQL},
		{Parameters: "[map[parameters:map[] query:SELECT * FROM USER WHERE name = 'k2user']]", CaseType: secConfig.SQL},
		{Parameters: "[map[parameters:map[] query:SELECT * FROM USER WHERE id = 2]]", CaseType: secConfig.SQL},
	}
	secConfig.ValidateResult(expectedData, t)
}

func TestSQLConnHook(t *testing.T) {

	secConfig.RegisterListener()
	var db *sql.DB
	db, err := sql.Open("sqlite3", "./sec_test.db")
	if err != nil {
		t.Error(err)
	}
	defer db.Close()
	conn, err := db.Conn(context.Background())
	if err != nil {
		log.Fatal(err)
		return
	}
	// defer conn.Close()

	statement, err := conn.PrepareContext(context.Background(), "CREATE TABLE IF NOT EXISTS USER (id INTEGER, name TEXT)")
	if err != nil {
		t.Error(err)
		return
	}
	defer statement.Close()
	statement.Exec()

	conn.ExecContext(context.Background(), "insert into USER values(3,'nruser')")

	_, err = conn.QueryContext(context.Background(), "SELECT * FROM USER WHERE name = 'nruser'")
	if err != nil {
		t.Error(err)
	}

	statement2, err := conn.PrepareContext(context.Background(), "SELECT * FROM USER WHERE id = 3")

	if err != nil {
		t.Error(err)
	}

	_, err = statement2.Query()
	defer statement2.Close()

	if err != nil {
		t.Error(err)
	}

	var expectedData = []secConfig.TestArgs{
		{Parameters: "[map[parameters:map[] query:CREATE TABLE IF NOT EXISTS USER (id INTEGER, name TEXT)]]", CaseType: secConfig.SQL},
		{Parameters: "[map[parameters:map[] query:insert into USER values(3,'nruser')]]", CaseType: secConfig.SQL},
		{Parameters: "[map[parameters:map[] query:SELECT * FROM USER WHERE name = 'nruser']]", CaseType: secConfig.SQL},
		{Parameters: "[map[parameters:map[] query:SELECT * FROM USER WHERE id = 3]]", CaseType: secConfig.SQL},
	}
	secConfig.ValidateResult(expectedData, t)
}

func TestSQLTxHook(t *testing.T) {

	secConfig.RegisterListener()
	var db *sql.DB
	db, err := sql.Open("sqlite3", "./sec_test.db")
	if err != nil {
		t.Error(err)
	}
	defer db.Close()

	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Error(err)
	}

	statement, err := tx.PrepareContext(context.Background(), "CREATE TABLE IF NOT EXISTS USER (id INTEGER, name TEXT)")
	if err != nil {
		t.Error(err)
	}
	defer statement.Close()
	statement.Exec()

	tx.ExecContext(context.Background(), "insert into USER values(4,'intuser')")

	_, err = tx.QueryContext(context.Background(), "SELECT * FROM USER WHERE name = 'intuser'")
	if err != nil {
		t.Error(err)
	}

	statement2, err := tx.PrepareContext(context.Background(), "SELECT * FROM USER WHERE id = 4")

	if err != nil {
		t.Error(err)
	}

	_, err = statement2.Query()
	defer statement2.Close()

	if err != nil {
		t.Error(err)
	}

	defer tx.Commit()

	var expectedData = []secConfig.TestArgs{
		{Parameters: "[map[parameters:map[] query:CREATE TABLE IF NOT EXISTS USER (id INTEGER, name TEXT)]]", CaseType: secConfig.SQL},
		{Parameters: "[map[parameters:map[] query:insert into USER values(4,'intuser')]]", CaseType: secConfig.SQL},
		{Parameters: "[map[parameters:map[] query:SELECT * FROM USER WHERE name = 'intuser']]", CaseType: secConfig.SQL},
		{Parameters: "[map[parameters:map[] query:SELECT * FROM USER WHERE id = 4]]", CaseType: secConfig.SQL},
	}
	secConfig.ValidateResult(expectedData, t)
}
