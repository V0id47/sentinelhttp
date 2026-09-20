package cookieanalysis

import (
	"strconv"
	"strings"
	"time"
)

// parseCookieDate implements the tolerant cookie-date token algorithm from
// RFC6265bis rather than treating Expires as an HTTP Date grammar.
func parseCookieDate(value string) (time.Time, bool) {
	var hour, minute, second, day, month, year int
	var foundTime, foundDay, foundMonth, foundYear bool
	for _, token := range dateTokens(value) {
		lower := strings.ToLower(token)
		if !foundTime {
			if h, m, s, ok := parseHMS(token); ok {
				hour, minute, second, foundTime = h, m, s, true
				continue
			}
		}
		if !foundDay {
			if n, ok := leadingDecimal(token, 1, 2); ok {
				day, foundDay = n, true
				continue
			}
		}
		if !foundMonth && len(lower) >= 3 {
			months := map[string]int{"jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6, "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12}
			if n, ok := months[lower[:3]]; ok {
				month, foundMonth = n, true
				continue
			}
		}
		if !foundYear {
			if n, ok := leadingDecimal(token, 2, 4); ok {
				year, foundYear = n, true
			}
		}
	}
	if year >= 70 && year <= 99 {
		year += 1900
	} else if year <= 69 {
		year += 2000
	}
	if !foundTime || !foundDay || !foundMonth || !foundYear || year < 1601 || day < 1 || day > 31 || hour > 23 || minute > 59 || second > 59 {
		return time.Time{}, false
	}
	result := time.Date(year, time.Month(month), day, hour, minute, second, 0, time.UTC)
	if result.Year() != year || int(result.Month()) != month || result.Day() != day {
		return time.Time{}, false
	}
	return result, true
}

func dateTokens(value string) []string {
	var tokens []string
	start := -1
	for index := 0; index <= len(value); index++ {
		delimiter := index == len(value) || isDateDelimiter(value[index])
		if delimiter {
			if start >= 0 {
				tokens = append(tokens, value[start:index])
				start = -1
			}
		} else if start < 0 {
			start = index
		}
	}
	return tokens
}

func isDateDelimiter(b byte) bool {
	return b == 0x09 || b >= 0x20 && b <= 0x2f || b >= 0x3b && b <= 0x40 || b >= 0x5b && b <= 0x60 || b >= 0x7b && b <= 0x7e
}

func decimal(value string, minDigits, maxDigits int) (int, bool) {
	if len(value) < minDigits || len(value) > maxDigits {
		return 0, false
	}
	for i := range value {
		if value[i] < '0' || value[i] > '9' {
			return 0, false
		}
	}
	n, err := strconv.Atoi(value)
	return n, err == nil
}

func leadingDecimal(value string, minDigits, maxDigits int) (int, bool) {
	digits := 0
	for digits < len(value) && digits < maxDigits && value[digits] >= '0' && value[digits] <= '9' {
		digits++
	}
	if digits < minDigits || digits < len(value) && value[digits] >= '0' && value[digits] <= '9' {
		return 0, false
	}
	n, err := strconv.Atoi(value[:digits])
	return n, err == nil
}

func parseHMS(value string) (int, int, int, bool) {
	first := strings.IndexByte(value, ':')
	if first < 0 {
		return 0, 0, 0, false
	}
	hour, ok := decimal(value[:first], 1, 2)
	if !ok {
		return 0, 0, 0, false
	}
	rest := value[first+1:]
	second := strings.IndexByte(rest, ':')
	if second < 0 {
		return 0, 0, 0, false
	}
	minute, ok := decimal(rest[:second], 1, 2)
	if !ok {
		return 0, 0, 0, false
	}
	secondValue, ok := leadingDecimal(rest[second+1:], 1, 2)
	return hour, minute, secondValue, ok
}
