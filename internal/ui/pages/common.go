package pages

import "strings"

func generatePlaceholder(digits int) string {
	sb := strings.Builder{}
	for i := 1; i <= digits; i++ {
		sb.WriteString("0")
	}

	return sb.String()
}
