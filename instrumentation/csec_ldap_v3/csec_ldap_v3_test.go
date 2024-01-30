// Copyright 2023 New Relic Corporation. All rights reserved.
// SPDX-License-Identifier: New Relic Software License v1.0
package csec_ldap_v3

import (
	"fmt"
	"testing"

	"github.com/go-ldap/ldap/v3"
	_ "github.com/newrelic/csec-go-agent"
	secConfig "github.com/newrelic/csec-go-agent/security_config"
)

func TestLDAPSearchHook(t *testing.T) {
	secConfig.RegisterListener()
	lDapConn, err := ldap.Dial("tcp", fmt.Sprintf("%s:%d", "ldap.forumsys.com", 389))

	if err != nil {
		t.Error(err)
	}
	defer lDapConn.Close()
	baseDN := "ou=mathematicians,dc=example,dc=com"
	filter := fmt.Sprintf("(uid==%s)", "gauss")
	searchReq := ldap.NewSearchRequest(baseDN, ldap.ScopeWholeSubtree, 0, 0, 0,
		false, filter, []string{}, nil)

	_, err = lDapConn.Search(searchReq)
	if err != nil {
		t.Error(err)
	}
	var expectedData = []secConfig.TestArgs{
		{Parameters: "[map[filter:(uid==gauss)]]", CaseType: secConfig.LDAP},
	}
	secConfig.ValidateResult(expectedData, t)
}

func TestLDAPModifyHook(t *testing.T) {
	secConfig.RegisterListener()
	lDapConn, err := ldap.Dial("tcp", fmt.Sprintf("%s:%d", "ldap.forumsys.com", 389))
	if err != nil {
		t.Error(err)
	}
	defer lDapConn.Close()
	baseDN := "ou=mathematicians,dc=example,dc=com"
	searchReq := ldap.NewModifyRequest(baseDN, nil)
	searchReq.Add("description", []string{"An example user"})
	searchReq.Replace("mail", []string{"user@example.org"})

	lDapConn.Modify(searchReq)
	if err != nil {
		t.Error(err)
	}
	var expectedData = []secConfig.TestArgs{
		{Parameters: "[map[filter:ou=mathematicians,dc=example,dc=com]]", CaseType: secConfig.LDAP},
	}
	secConfig.ValidateResult(expectedData, t)
}
