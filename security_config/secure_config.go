// Copyright 2023 New Relic Corporation. All rights reserved.
// SPDX-License-Identifier: New Relic Software License v1.0

package security_config

type Security struct {
	Enabled               bool   `json:"enabled"`
	Mode                  string `json:"mode"`
	Validator_service_url string `json:"validator_service_url"`
	Agent                 struct {
		Enabled bool `json:"enabled"`
	} `json:"agent"`
	Detection struct {
		Rci struct {
			Enabled bool `json:"enabled"`
		} `json:"rci"`
		Rxss struct {
			Enabled bool `json:"enabled"`
		} `json:"rxss"`
		Deserialization struct {
			Enabled bool `json:"enabled"`
		} `json:"deserialization"`
	} `json:"detection"`
	SecurityHomePath string `json:"-"` // SecurityHomePath not part of user config file default is pwd
	Request          struct {
		BodyLimit int `yaml:"body_limit"`
	} `yaml:"request"`

	ExcludeFromIastScan struct {
		API                   []string `yaml:"api"`
		HttpRequestParameters struct {
			Header []string `yaml:"header" json:"header"`
			Query  []string `yaml:"query" json:"query"`
			Body   []string `yaml:"body" json:"body"`
		} `yaml:"http_request_parameters"`
		IastDetectionCategory struct {
			InsecureSettings    bool `yaml:"insecure_settings"`
			InvalidFileAccess   bool `yaml:"invalid_file_access"`
			SQLInjection        bool `yaml:"sql_injection"`
			NosqlInjection      bool `yaml:"nosql_injection"`
			LdapInjection       bool `yaml:"ldap_injection"`
			JavascriptInjection bool `yaml:"javascript_injection"`
			CommandInjection    bool `yaml:"command_injection"`
			XpathInjection      bool `yaml:"xpath_injection"`
			Ssrf                bool `yaml:"ssrf"`
			Rxss                bool `yaml:"rxss"`
		} `yaml:"iast_detection_category"`
	} `yaml:"exclude_from_iast_scan"`
	ScanSchedule struct {
		Delay                     int    `yaml:"delay"`
		Duration                  int    `yaml:"duration"`
		Schedule                  string `yaml:"schedule"`
		AllowIastSampleCollection bool   `yaml:"allow_iast_sample_collection"`
	} `yaml:"scan_schedule"`
}

type Policy struct {
	Enforce            bool   `json:"enforce" yaml:"enforce"`
	Version            string `json:"version" yaml:"version"`
	PolicyPull         bool   `json:"policyPull" yaml:"policyPull"`
	PolicyPullInterval int    `json:"policyPullInterval" yaml:"policyPullInterval"`
	VulnerabilityScan  struct {
		Enabled  bool `json:"enabled" yaml:"enabled"`
		IastScan struct {
			Enabled bool `json:"enabled" yaml:"enabled"`
			Probing struct {
				Interval  int `json:"interval" yaml:"interval"`
				BatchSize int `json:"batchSize" yaml:"batchSize"`
			} `json:"probing" yaml:"probing"`
		} `json:"iastScan" yaml:"iastScan"`
	} `json:"vulnerabilityScan" yaml:"vulnerabilityScan"`
	ProtectionMode struct {
		Enabled    bool `json:"enabled" yaml:"enabled"`
		IPBlocking struct {
			Enabled            bool `json:"enabled" yaml:"enabled"`
			AttackerIPBlocking bool `json:"attackerIpBlocking" yaml:"attackerIpBlocking"`
			IPDetectViaXFF     bool `json:"ipDetectViaXFF" yaml:"ipDetectViaXFF"`
		} `json:"ipBlocking" yaml:"ipBlocking"`
		APIBlocking struct {
			Enabled                    bool `json:"enabled" yaml:"enabled"`
			ProtectAllApis             bool `json:"protectAllApis" yaml:"protectAllApis"`
			ProtectKnownVulnerableApis bool `json:"protectKnownVulnerableApis" yaml:"protectKnownVulnerableApis"`
			ProtectAttackedApis        bool `json:"protectAttackedApis" yaml:"protectAttackedApis"`
		} `json:"apiBlocking" yaml:"apiBlocking"`
	} `json:"protectionMode" yaml:"protectionMode"`
	SendCompleteStackTrace    bool `json:"sendCompleteStackTrace" yaml:"sendCompleteStackTrace"`
	EnableHTTPRequestPrinting bool `json:"enableHTTPRequestPrinting" yaml:"enableHTTPRequestPrinting"`
}
