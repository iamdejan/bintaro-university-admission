package pages

import (
	"fmt"
	"strings"
)

func generatePlaceholder(digits int) string {
	sb := strings.Builder{}
	for i := 1; i <= digits; i++ {
		sb.WriteString("0")
	}

	return sb.String()
}

func generateRegexValidation(digits int) string {
	return fmt.Sprintf("[0-9]{%d}", digits)
}
