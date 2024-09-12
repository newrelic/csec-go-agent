package security_utils

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strings"
)

func XmlToMapParser(xmlVal []byte) (map[string][]string, error) {

	var result = make(map[string][]string)
	if len(xmlVal) < 0 {
		return result, nil
	}

	b := bytes.NewReader(xmlVal)
	p := xml.NewDecoder(b)
	err := xmlToMapParser("", p, &result)
	return result, err

}

func JsonToMapParser(jsonStr string) (map[string][]string, error) {

	var result = make(map[string][]string)

	jsonMap := make(map[string]interface{})
	err := json.Unmarshal([]byte(jsonStr), &jsonMap)
	if err == nil {
		jsonToMapParser("", jsonMap, &result)
		return result, nil
	} else {
		var arrayJsonMap []map[string]interface{}
		err = json.Unmarshal([]byte(jsonStr), &arrayJsonMap)
		if err == nil {
			jsonToMapParserArray("", arrayJsonMap, &result)
			return result, nil
		} else {
			return nil, err
		}
	}

}

func xmlToMapParser(parent string, p *xml.Decoder, result *map[string][]string) error {
	for {
		t, err := p.Token()
		if err != nil {
			if err != io.EOF {
				return errors.New("xml.Decoder.Token() - " + err.Error())
			}
			return err
		}
		switch tt := t.(type) {

		case xml.StartElement:
			if parent == "" {
				return xmlToMapParser(tt.Name.Local, p, result)
			}
			xmlToMapParser(parent+"."+tt.Name.Local, p, result)
		case xml.EndElement:
			return nil
		case xml.CharData:
			value := strings.Trim(string(tt), "\t\r\b\n ")
			if value != "" {
				if val, ok := (*result)[parent]; ok {
					val = append(val, value)
					(*result)[parent] = val
				} else {
					a := []string{}
					a = append(a, value)
					(*result)[parent] = a
				}
			}
		default:

		}
	}
}

func jsonToMapParserArray(parent string, jsonMap []map[string]interface{}, result *map[string][]string) {
	for _, value := range jsonMap {
		jsonToMapParser("[]", value, result)
	}
}

func jsonToMapParser(parent string, jsonMap map[string]interface{}, result *map[string][]string) {

	par := parent
	for key, value := range jsonMap {

		if par == "" {
			par = key
		} else {
			par = parent + "." + key
		}

		switch value := value.(type) {

		case map[string]interface{}:
			jsonToMapParser(par, value, result)
			continue
		case []interface{}:
			for _, data := range value {

				if mv, ok := data.(map[string]interface{}); ok {
					jsonToMapParser(par+"[]", mv, result)
				} else {
					value := fmt.Sprint(data)
					push(par, value, result)
				}
			}
			continue
		default:
			push(par, value, result)
		}

	}

}

func push(key string, val any, result *map[string][]string) {
	value := fmt.Sprint(val)

	if value != "" {
		if val, ok := (*result)[key]; ok {
			val = append(val, value)
			(*result)[key] = val
		} else {
			a := []string{}
			a = append(a, value)
			(*result)[key] = a
		}
	}
}
