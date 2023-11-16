// Copyright 2023 New Relic Corporation. All rights reserved.
// SPDX-License-Identifier: New Relic Pre-Release

package security_utils

import (
	"encoding/json"
	"html"
	"net/url"
	"regexp"
	"strings"

	"github.com/dlclark/regexp2"
)

const (
	UNICODE_MAX                       = 0x10FFFF
	HTML_COMMENT_END                  = "-->"
	HTML_COMMENT_START                = "!--"
	ANGLE_END                         = ">"
	ON                                = "on"
	JAVASCRIPT                        = "javascript:"
	JS                                = ".js"
	HTTP                              = "http://"
	HTTPS                             = "https://"
	FIVE_COLON                        = "::::"
	APPLICATION_JSON                  = "application/json"
	APPLICATION_XML                   = "application/xml"
	APPLICATION_X_WWW_FORM_URLENCODED = "application/x-www-form-urlencoded"
	SCRIPT                            = "script"
	SCRIPT_END                        = "</script"
	ON1                               = "on"
	SRC                               = "src"
	HREF                              = "href"
	ANGLE_END_CHAR                    = '>'
	ACTION                            = "action"
	EQUALS                            = "="
	ANGLE_START                       = "<"
	ANGLE_START_URL_ENCODED_UPPERCASE = "%3C"
	FORMACTION                        = "formaction"
	SRCDOC                            = "srcdoc"
	DATA                              = "data"
	CAME_TO_XSS_CHECK                 = "Came to XSS check : "
	DOUBLE_SEMICOLON                  = ";;"
	REGEX_SPACE                       = "\\s+"
)

func IsContentTypeSupported(type1 string) bool {
	supportedContentType := []string{
		"text/css",
		"text/csv",
		"text/html",
		"text/javascript",
		"application/json",
		"application/ld+json",
		"text/javascript",
		"application/vnd.oasis.opendocument.text",
		"application/x-httpd-php",
		"application/rtf",
		"image/svg+xml",
		"text/plain",
		"application/xhtml+xml",
		"application/xml",
		"multipart/form-data",
		"application/x-www-form-urlencoded",
		"application/octet-stream",
	}

	return ContainsInArray(supportedContentType, strings.ToLower(type1))
}

var tagNameRegex = regexp.MustCompile(`(?ims)<([a-zA-Z_\\-]+[0-9]*|!--)`)
var attribRegex = regexp2.MustCompile("(?ims)([^(\\/\\s<'\">)]+?)(?:\\s*)=\\s*(('|\")([\\s\\S]*?)(?:(?=(\\\\?))\\5.)*?\\3|.+?(?=\\/>|>|\\?>|\\s|<\\/|$))", 0)

func safeDecode(data string) string {
	decodedData, err := url.Parse(data)
	if err != nil {
		return ""
	}
	return decodedData.String()
}
func processURLEncodedDataForXSS(data string) []string {
	var processedData []string
	key := data
	oldkey := ""
	for oldkey != key {
		if strings.Contains(key, ANGLE_START) {
			processedData = append(processedData, key)
		}
		oldkey = key
		key = safeDecode(key)
	}
	return processedData
}

func getXSSConstructs(data string) []string {
	var construct []string
	isAttackConstruct := false

	currPos := 0
	startPos := 0
	tmpCurrPos := 0
	tmpStartPos := 0

	for currPos < len(data) {
		matchesindex := tagNameRegex.FindStringSubmatchIndex(data[currPos:])
		if len(matchesindex) == 0 {
			return construct
		}
		isAttackConstruct = false

		if len(matchesindex) < 4 {
			return construct
		}
		matchesindex[0] += currPos
		matchesindex[1] += currPos
		matchesindex[2] += currPos
		matchesindex[3] += currPos

		tagName := data[matchesindex[2]:matchesindex[3]]
		if tagName == "" {
			return construct
		}
		startPos = matchesindex[0]
		if startPos == -1 {
			return construct
		}
		currPos = matchesindex[1] - 1
		if strings.Compare(tagName, HTML_COMMENT_START) == 0 {

			tmpCurrPos = strings.Index(data[startPos:], HTML_COMMENT_END)
			if tmpCurrPos == -1 {
				break
			} else {
				currPos = tmpCurrPos + startPos
				//tmpCurrPos = currPos

				continue
			}
		}
		tmpCurrPos = strings.Index(data[startPos:], ANGLE_END)

		if tmpCurrPos == -1 {
			tmpStartPos = startPos
		} else {
			tmpCurrPos += startPos
			tmpStartPos = tmpCurrPos
		}
		matchessecound, _ := attribRegex.FindStringMatch(data[currPos:])

		if matchessecound != nil {

			for matchessecound != nil {
				gps := matchessecound.Groups()
				if len(gps) < 3 {
					break
				}
				if len(gps[0].Captures) < 1 {
					break
				}

				attribData := gps[0].String()
				if attribData == "" {
					break
				}
				start := gps[0].Captures[0].Index + currPos
				end := start + gps[0].Captures[0].Length
				currPos = end - 1

				counter := strings.Index(data[tmpStartPos:], ANGLE_END)

				if counter != -1 {
					tmpCurrPos = tmpStartPos + counter
				} else {
					tmpCurrPos = counter
				}

				if tmpCurrPos == -1 || start < tmpCurrPos {
					tmpCurrPos = end - 1
					tmpStartPos = tmpCurrPos
					tmpStartPos++

					if gps[3].String() == "" && end >= tmpCurrPos {
						find := strings.Index(data[start:], ANGLE_END)
						if find == -1 {
							tmpStartPos = len(data) - 1
							tmpCurrPos = -1
						} else {
							tmpStartPos = find + start
							tmpCurrPos = tmpStartPos
						}

						tmp := tmpStartPos
						if tmp >= len(attribData) {

							tmp = len(attribData)
						}

						attribData = attribData[0:tmp]
					}

					kval := strings.Split(attribData, EQUALS)
					var key string
					var val string
					if len(kval) > 0 {
						key = kval[0]

					}
					if len(kval) > 1 {
						val = strings.Join(kval[1:], EQUALS)
					}

					if key != "" && strings.HasPrefix(strings.ToLower(key), ON) || CaseInsensitiveEquals(key, SRC) || CaseInsensitiveEquals(key, HREF) || CaseInsensitiveEquals(key, ACTION) || CaseInsensitiveEquals(key, FORMACTION) || CaseInsensitiveEquals(key, SRCDOC) || CaseInsensitiveEquals(key, DATA) || CaseInsensitiveContains(strings.ReplaceAll(html.UnescapeString(val), REGEX_SPACE, ""), JAVASCRIPT) {
						isAttackConstruct = true
					}

				} else {
					break
				}
				matchessecound, _ = attribRegex.FindStringMatch(data[currPos:])
			}
		}

		if tmpCurrPos > 0 {
			currPos = tmpCurrPos
		}
		if data[currPos] != ANGLE_END_CHAR {
			tmp := strings.Index(string(data[currPos:]), ANGLE_END)
			if tmp != -1 {
				currPos = tmp + currPos
			} else if !isAttackConstruct {
				continue
			}
		}
		if CaseInsensitiveEquals(strings.TrimSpace(tagName), SCRIPT) {
			locationOfEndTag := currPos + strings.Index(strings.ToLower(data[currPos:]), SCRIPT_END)
			if locationOfEndTag > currPos {
				body := data[currPos+1 : locationOfEndTag]
				if body != "" {
					construct = append(construct, data[startPos:currPos+1]+body)
				}
			} else {
				body := data[currPos+1:]
				tagEnd := strings.Index(string(body), ANGLE_END)
				if body != "" && tagEnd != -1 {
					body := data[tagEnd:]
					construct = append(construct, data[startPos:currPos+1]+body)
				}

			}
		}

		if isAttackConstruct {
			construct = append(construct, data[startPos:currPos+1])
		}
	}
	return construct
}

func IsXSS(combinedData string) []string {
	return getXSSConstructs(combinedData)
}

func decodeRequestData(rq *Info_req) []string {
	var processedData []string
	for k, v := range rq.Request.Headers {
		kVal := processURLEncodedDataForXSS(k)
		processedData = append(processedData, kVal...)
		vVal := processURLEncodedDataForXSS(v)
		processedData = append(processedData, vVal...)
	}
	for k, v := range rq.Request.ParameterMap {
		kVal := processURLEncodedDataForXSS(k)
		processedData = append(processedData, kVal...)
		for i := 0; i < len(v); i++ {
			vVal := processURLEncodedDataForXSS(v[i])
			processedData = append(processedData, vVal...)
		}
	}

	vVal := processURLEncodedDataForXSS(rq.Request.URL)
	processedData = append(processedData, vVal...)
	body := ""
	if rq.Request.BodyReader.GetBody != nil {
		body = string(rq.Request.BodyReader.GetBody())
	}
	contentType := rq.Request.ContentType
	if body != "" {
		processedData = append(processedData, body)
		switch contentType {
		case "application/json":
			data := make(map[string]json.RawMessage)
			err := json.Unmarshal([]byte(body), &data)
			if err != nil {
				break
			}
			for key, value := range data {
				processedData = append(processedData, key)
				processedData = append(processedData, string(value))
			}
		case "application/xml":
			processedData = append(processedData, body)
		case "application/x-www-form-urlencoded":
			unescapedString, err := url.QueryUnescape(body)
			if err != nil {
				break
			}
			if !CaseInsensitiveEquals(unescapedString, body) && strings.Contains(unescapedString, ANGLE_START) {
				processedData = append(processedData, unescapedString)
			}
		}

	}
	return processedData

}

func decodeResponseData(rq *Info_req) []string {
	var processedData []string
	decodedBodyValue := processURLEncodedDataForXSS(rq.ResponseBody)
	processedData = append(processedData, decodedBodyValue...)
	for _, st := range decodedBodyValue {
		newprocessedBody := safeDecode(st)
		if !(st == newprocessedBody) && strings.Contains(newprocessedBody, ANGLE_START) {
			processedData = append(processedData, newprocessedBody)
		}
	}

	return processedData
}

func CheckForReflectedXSS(req *Info_req) string {

	if req == nil {
		return ""
	}
	combinedRequestData := decodeRequestData(req)
	combinedRequestDataStr := strings.Join(combinedRequestData, FIVE_COLON)
	combinedResponseData := decodeResponseData(req)
	combinedResponseDataStr := strings.Join(combinedResponseData, FIVE_COLON)
	attackConstructs := IsXSS(combinedRequestDataStr)

	toReturn := ""
	for _, val := range attackConstructs {
		if strings.Contains(strings.ToLower(combinedResponseDataStr), strings.ToLower(val)) {
			toReturn = val
			break
		}
	}
	if toReturn != "" {
		responseConstructs := IsXSS(combinedResponseDataStr)

		for _, val := range responseConstructs {
			if strings.Contains(strings.ToLower(toReturn), strings.ToLower(val)) {
				toReturn = val
				break
			}
		}
	}
	return toReturn
}
