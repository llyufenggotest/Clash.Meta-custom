package outbound

import (
	"fmt"
	"strconv"
	"strings"
)

// Only numeric business codes and a closed vocabulary may cross the private response boundary.
func blackstoneAdmissionError(status int, response map[string]any, stage string) error {
	code := "unknown"
	switch v := response["code"].(type) {
	case float64:
		code = strconv.FormatFloat(v, 'f', 0, 64)
	case string:
		if n, e := strconv.ParseInt(v, 10, 64); e == nil {
			code = strconv.FormatInt(n, 10)
		}
	}
	message := "redacted"
	for _, key := range []string{"message", "msg"} {
		if m, ok := response[key].(string); ok {
			switch strings.ToLower(strings.TrimSpace(m)) {
			case "unauthorized", "forbidden", "invalid token", "token expired":
				message = strings.ReplaceAll(strings.ToLower(strings.TrimSpace(m)), " ", "_")
			}
		}
	}
	return fmt.Errorf("control response http=%d business=%s message=%s; %s", status, code, message, stage)
}
