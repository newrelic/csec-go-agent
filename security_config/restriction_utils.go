package security_config

import (
	"net/url"
	"strings"

	secUtils "github.com/newrelic/csec-go-agent/internal/security_utils"
)

var CONTENT_TYPE_TEXT_JSON = "text/json"
var CONTENT_TYPE_TEXT_XML = "text/xml"
var CONTENT_TYPE_APPLICATION_JSON = "application/json"
var CONTENT_TYPE_APPLICATION_XML = "application/xml"
var CONTENT_TYPE_APPLICATION_X_WWW_FORM_URLENCODED = "application/x-www-form-urlencoded"

func HasValidAccountId(requestHeader, query map[string][]string, u string) bool {

	isValidAccountId := false

	isValidAccountId = isValidAccountId || headerRestrictionCheck(requestHeader)
	isValidAccountId = isValidAccountId || queryRestrictionCheck(query)
	isValidAccountId = isValidAccountId || pathRestrictionCheck(u)

	return isValidAccountId
}

func headerRestrictionCheck(requestHeader map[string][]string) bool {
	isEnabled, restrictedHeaders := GlobalInfo.RestrictionCriteriaHeader()
	if !isEnabled || len(restrictedHeaders) <= 0 {
		return false
	}
	return matcher(restrictedHeaders, requestHeader)
}

func queryRestrictionCheck(query map[string][]string) bool {
	isEnabled, restrictedQuery := GlobalInfo.RestrictionCriteriaQuery()
	if !isEnabled || len(restrictedQuery) <= 0 {
		return false
	}
	return matcher(restrictedQuery, query)

}

func pathRestrictionCheck(u string) bool {
	uri := u
	accountIds := GlobalInfo.RestrictionCriteriaAccountIDValue()
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

func BodyRestrictionCheck(body, contentType string) bool {

	isEnabled, restrictedBody := GlobalInfo.RestrictionCriteriaBody()

	if !isEnabled || body == "" || len(restrictedBody) <= 0 {
		return false
	}

	switch strings.ToLower(contentType) {
	case CONTENT_TYPE_TEXT_JSON:
	case CONTENT_TYPE_APPLICATION_JSON:

		key_value, err := secUtils.JsonToMapParser(body)
		if err == nil {
			return matcher(restrictedBody, key_value)
		}
		break
	case CONTENT_TYPE_APPLICATION_XML:
	case CONTENT_TYPE_TEXT_XML:

		key_value, err := secUtils.XmlToMapParser([]byte(body))
		if err == nil {
			return matcher(restrictedBody, key_value)
		}
		break
	case CONTENT_TYPE_APPLICATION_X_WWW_FORM_URLENCODED:
		key_value, err := url.ParseQuery(body)
		if err == nil {
			return matcher(restrictedBody, key_value)
		}
		break
	}

	return false

}

func matcher(attr []string, query map[string][]string) bool {
	if len(query) <= 0 {
		return false
	}
	for _, key := range attr {
		value, ok := query[key]
		if ok {
			accountIdMatcher(GlobalInfo.RestrictionCriteriaAccountIDValue(), value)
		}
	}
	return false
}

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
