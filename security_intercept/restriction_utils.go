package security_intercept

import (
	"strings"

	secUtils "github.com/newrelic/csec-go-agent/internal/security_utils"
	secConfig "github.com/newrelic/csec-go-agent/security_config"
)

func accountIdMatcher(accountIds, values []string) bool {

	for _, aid := range accountIds {
		for _, value := range values {
			if secUtils.CaseInsensitiveEquals(aid, value) {
				return true
			}
		}
	}
	return false

}

func headerRestrictionCheck(requestHeader map[string][]string) bool {
	restrictedHeaders := secConfig.GlobalInfo.RestrictionCriteriaHeader()
	if len(restrictedHeaders) <= 0 {
		return true
	}

	for _, restrictedHeader := range restrictedHeaders {

		value, ok := requestHeader[restrictedHeader] //check to verify the presence of restricted header in request headers
		if ok {
			accountIdMatcher(secConfig.GlobalInfo.RestrictionCriteriaAccountIDValue(), value)
		}
	}
	return false
}

func queryRestrictionCheck(query map[string][]string) bool {
	queryKey := secConfig.GlobalInfo.RestrictionCriteriaQuery()
	if len(query) <= 0 {
		return true
	}
	for k := range queryKey {
		key := queryKey[k]
		value, ok := query[key]
		if ok {
			accountIdMatcher(secConfig.GlobalInfo.RestrictionCriteriaAccountIDValue(), value)
		}
	}
	return false
}

func pathRestrictionCheck(u string) bool {
	uri := u
	accountIds := secConfig.GlobalInfo.RestrictionCriteriaAccountIDValue()
	for _, aid := range accountIds {
		if strings.HasSuffix(uri, "/"+aid) {
			return true
		}
		if strings.Contains(uri, "/"+aid+"/") {
			return true
		}
	}
	return false

}

func pathRestrictionBody(body string) bool {
	return true
}
