package security_implementation

import (
	"net/http"

	secUtils "github.com/newrelic/csec-go-agent/internal/security_utils"
	secConfig "github.com/newrelic/csec-go-agent/security_config"
)

func (k Secureimpl) DissociateInboundRequest(traceId string) []string {

	request := getRequestDoubleCheck(traceId)
	if request == nil {
		return make([]string, 0)
	} else {
		k.checkSecureCookies(request)
		k.xssCheck(request)
		disassociate(getID(), traceId)
		return request.RequestIdentifier.TempFiles
	}
}

func (k Secureimpl) checkSecureCookies(r *secUtils.Info_req) {
	if secConfig.GlobalInfo.IsInsecureSettingsDisabled() {
		return
	}

	responseHeader := r.ResponseHeader
	if responseHeader != nil {
		logger.Debugln("Verifying Secure Cookies in the response header.", responseHeader)
		tmpResponse := http.Response{Header: responseHeader}
		cookies := tmpResponse.Cookies()

		var arg []map[string]interface{}
		check := false
		for _, cookie := range cookies {
			check = true
			arg = append(arg, map[string]interface{}{
				"name":       cookie.Name,
				"isHttpOnly": cookie.HttpOnly,
				"isSecure":   cookie.Secure,
				"value":      cookie.Value,
			})
		}
		if check {
			k.SendLowSeverityEvent("SECURE_COOKIE", "SECURE_COOKIE", arg)
		}
	}
}

func (k Secureimpl) xssCheck(r *secUtils.Info_req) {
	if !secConfig.GlobalInfo.IsRxssDisabled() && r.ResponseBody != "" {

		contentType := r.ResponseContentType

		if !secUtils.IsContentTypeSupported(contentType) {
			// SendLogMessage(SKIP_RXSS_EVENT+contentType, "XssCheck", "SEVERE")
			logger.Debugln(SKIP_RXSS_EVENT, contentType)
			return
		}

		// Double check befor rxss event validation becouse in some case we don't have contentType in response header.
		cType := http.DetectContentType([]byte(r.ResponseBody))
		if !secUtils.IsContentTypeSupported(cType) {
			// SendLogMessage(SKIP_RXSS_EVENT+cType, "XssCheck", "SEVERE")
			logger.Debugln(SKIP_RXSS_EVENT, cType)
			return
		}

		if r.ResponseContentType == "" {
			r.ResponseContentType = cType
		}

		out := secUtils.CheckForReflectedXSS(r)
		logger.Debugln("RXSS check result: Out value set to ", out)

		if len(out) == 0 && !secConfig.GlobalInfo.IsIASTEnable() {
			logger.Debugln("No need to send xss event as not attack and dynamic scanning is false")
		} else {
			var arg []string
			arg = append(arg, out)
			arg = append(arg, r.ResponseBody)
			k.SendEvent("REFLECTED_XSS", "REFLECTED_XSS", arg)
		}
	}

}
