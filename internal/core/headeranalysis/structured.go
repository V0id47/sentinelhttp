package headeranalysis

import (
	"encoding/base64"
	"strings"
	"unicode/utf8"
)

type sfKind uint8

const (
	sfInteger sfKind = iota
	sfDecimal
	sfString
	sfToken
	sfBinary
	sfBoolean
	sfDate
	sfDisplayString
)

type sfBare struct {
	kind  sfKind
	value string
}

type sfParameter struct {
	key   string
	value sfBare
}

type sfItemValue struct {
	bare   sfBare
	params []sfParameter
}

type sfMember struct {
	inner    bool
	items    []sfItemValue
	item     sfItemValue
	params   []sfParameter
	repeated bool
}

type sfDictionaryEntry struct {
	key    string
	member sfMember
}

type sfParser struct {
	input string
	pos   int
}

func parseSFItemField(value string) (sfItemValue, bool) {
	p := sfParser{input: value}
	p.skipSP()
	item, ok := p.parseItem()
	if !ok {
		return sfItemValue{}, false
	}
	p.skipSP()
	return item, p.pos == len(p.input)
}

func parseSFDictionary(value string) ([]sfDictionaryEntry, bool) {
	p := sfParser{input: value}
	p.skipSP()
	if p.pos == len(p.input) {
		return nil, true
	}
	positions := make(map[string]int)
	var entries []sfDictionaryEntry
	for {
		key, ok := p.parseKey()
		if !ok {
			return nil, false
		}
		var member sfMember
		if p.consume('=') {
			member, ok = p.parseMemberValue()
		} else {
			params, valid := p.parseParameters()
			ok = valid
			member.item = sfItemValue{bare: sfBare{kind: sfBoolean, value: "true"}, params: params}
		}
		if !ok {
			return nil, false
		}
		if position, exists := positions[key]; exists {
			member.repeated = true
			entries[position].member = member
		} else {
			positions[key] = len(entries)
			entries = append(entries, sfDictionaryEntry{key: key, member: member})
		}
		p.skipOWS()
		if p.pos == len(p.input) {
			return entries, true
		}
		if !p.consume(',') {
			return nil, false
		}
		p.skipOWS()
		if p.pos == len(p.input) {
			return nil, false
		}
	}
}

func (p *sfParser) parseMemberValue() (sfMember, bool) {
	if p.peek() == '(' {
		items, params, ok := p.parseInnerList()
		return sfMember{inner: true, items: items, params: params}, ok
	}
	item, ok := p.parseItem()
	return sfMember{item: item}, ok
}

func (p *sfParser) parseInnerList() ([]sfItemValue, []sfParameter, bool) {
	if !p.consume('(') {
		return nil, nil, false
	}
	p.skipSP()
	var items []sfItemValue
	for p.peek() != ')' {
		if p.pos == len(p.input) {
			return nil, nil, false
		}
		item, ok := p.parseItem()
		if !ok {
			return nil, nil, false
		}
		items = append(items, item)
		if p.peek() == ')' {
			break
		}
		if p.peek() != ' ' {
			return nil, nil, false
		}
		p.skipSP()
	}
	if !p.consume(')') {
		return nil, nil, false
	}
	params, ok := p.parseParameters()
	return items, params, ok
}

func (p *sfParser) parseItem() (sfItemValue, bool) {
	bare, ok := p.parseBareItem()
	if !ok {
		return sfItemValue{}, false
	}
	params, ok := p.parseParameters()
	return sfItemValue{bare: bare, params: params}, ok
}

func (p *sfParser) parseParameters() ([]sfParameter, bool) {
	positions := make(map[string]int)
	var params []sfParameter
	for p.consume(';') {
		p.skipSP()
		key, ok := p.parseKey()
		if !ok {
			return nil, false
		}
		value := sfBare{kind: sfBoolean, value: "true"}
		if p.consume('=') {
			value, ok = p.parseBareItem()
			if !ok {
				return nil, false
			}
		}
		if position, exists := positions[key]; exists {
			params[position].value = value
		} else {
			positions[key] = len(params)
			params = append(params, sfParameter{key: key, value: value})
		}
	}
	return params, true
}

func (p *sfParser) parseBareItem() (sfBare, bool) {
	switch first := p.peek(); {
	case first == '-' || first >= '0' && first <= '9':
		return p.parseNumber()
	case first == '"':
		return p.parseString()
	case isAlpha(first) || first == '*':
		return p.parseToken()
	case first == ':':
		return p.parseBinary()
	case first == '?':
		return p.parseBoolean()
	case first == '@':
		return p.parseDate()
	case first == '%':
		return p.parseDisplayString()
	default:
		return sfBare{}, false
	}
}

func (p *sfParser) parseNumber() (sfBare, bool) {
	start := p.pos
	if p.consume('-') && p.pos == len(p.input) {
		return sfBare{}, false
	}
	digitStart := p.pos
	for isDigit(p.peek()) {
		p.pos++
	}
	wholeDigits := p.pos - digitStart
	if wholeDigits == 0 {
		return sfBare{}, false
	}
	if p.consume('.') {
		fractionStart := p.pos
		for isDigit(p.peek()) {
			p.pos++
		}
		fractionDigits := p.pos - fractionStart
		if wholeDigits > 12 || fractionDigits < 1 || fractionDigits > 3 {
			return sfBare{}, false
		}
		return sfBare{kind: sfDecimal, value: p.input[start:p.pos]}, true
	}
	if wholeDigits > 15 {
		return sfBare{}, false
	}
	return sfBare{kind: sfInteger, value: p.input[start:p.pos]}, true
}

func (p *sfParser) parseString() (sfBare, bool) {
	if !p.consume('"') {
		return sfBare{}, false
	}
	var out strings.Builder
	for p.pos < len(p.input) {
		b := p.input[p.pos]
		p.pos++
		if b == '"' {
			return sfBare{kind: sfString, value: out.String()}, true
		}
		if b == '\\' {
			if p.pos == len(p.input) || p.input[p.pos] != '\\' && p.input[p.pos] != '"' {
				return sfBare{}, false
			}
			b = p.input[p.pos]
			p.pos++
		} else if b < 0x20 || b > 0x7e {
			return sfBare{}, false
		}
		out.WriteByte(b)
	}
	return sfBare{}, false
}

func (p *sfParser) parseToken() (sfBare, bool) {
	start := p.pos
	p.pos++
	for validSFTokenRest(p.peek()) {
		p.pos++
	}
	return sfBare{kind: sfToken, value: p.input[start:p.pos]}, true
}

func (p *sfParser) parseBinary() (sfBare, bool) {
	p.pos++
	start := p.pos
	for p.pos < len(p.input) && p.input[p.pos] != ':' {
		b := p.input[p.pos]
		if !(isAlpha(b) || isDigit(b) || b == '+' || b == '/' || b == '=') {
			return sfBare{}, false
		}
		p.pos++
	}
	if !p.consume(':') {
		return sfBare{}, false
	}
	encoded := p.input[start : p.pos-1]
	base := encoded
	providedPadding := 0
	if firstPadding := strings.IndexByte(encoded, '='); firstPadding >= 0 {
		base = encoded[:firstPadding]
		providedPadding = len(encoded) - firstPadding
		if strings.Trim(encoded[firstPadding:], "=") != "" {
			return sfBare{}, false
		}
	}
	neededPadding := (4 - len(base)%4) % 4
	if neededPadding == 3 || providedPadding > neededPadding {
		return sfBare{}, false
	}
	if _, err := base64.StdEncoding.DecodeString(base + strings.Repeat("=", neededPadding)); err != nil {
		return sfBare{}, false
	}
	return sfBare{kind: sfBinary, value: encoded}, true
}

func (p *sfParser) parseBoolean() (sfBare, bool) {
	if p.pos+2 > len(p.input) || p.input[p.pos] != '?' || p.input[p.pos+1] != '0' && p.input[p.pos+1] != '1' {
		return sfBare{}, false
	}
	value := p.input[p.pos+1] == '1'
	p.pos += 2
	if value {
		return sfBare{kind: sfBoolean, value: "true"}, true
	}
	return sfBare{kind: sfBoolean, value: "false"}, true
}

func (p *sfParser) parseDate() (sfBare, bool) {
	p.pos++
	number, ok := p.parseNumber()
	if !ok || number.kind != sfInteger {
		return sfBare{}, false
	}
	number.kind = sfDate
	return number, true
}

func (p *sfParser) parseDisplayString() (sfBare, bool) {
	if p.pos+2 > len(p.input) || p.input[p.pos] != '%' || p.input[p.pos+1] != '"' {
		return sfBare{}, false
	}
	p.pos += 2
	var out []byte
	for p.pos < len(p.input) {
		b := p.input[p.pos]
		p.pos++
		if b == '"' {
			if !utf8.Valid(out) {
				return sfBare{}, false
			}
			return sfBare{kind: sfDisplayString, value: string(out)}, true
		}
		if b == '%' {
			if p.pos+2 > len(p.input) {
				return sfBare{}, false
			}
			hi, hiOK := lowerHex(p.input[p.pos])
			lo, loOK := lowerHex(p.input[p.pos+1])
			if !hiOK || !loOK {
				return sfBare{}, false
			}
			out = append(out, hi<<4|lo)
			p.pos += 2
			continue
		}
		if !(b == '\\' || b >= 0x20 && b <= 0x21 || b >= 0x23 && b <= 0x24 || b >= 0x26 && b <= 0x5b || b >= 0x5d && b <= 0x7e) {
			return sfBare{}, false
		}
		out = append(out, b)
	}
	return sfBare{}, false
}

func (p *sfParser) parseKey() (string, bool) {
	start := p.pos
	first := p.peek()
	if !(first >= 'a' && first <= 'z' || first == '*') {
		return "", false
	}
	p.pos++
	for {
		b := p.peek()
		if !(b >= 'a' && b <= 'z' || isDigit(b) || strings.ContainsRune("_-.*", rune(b))) {
			break
		}
		p.pos++
	}
	return p.input[start:p.pos], true
}

func (p *sfParser) skipSP() {
	for p.peek() == ' ' {
		p.pos++
	}
}

func (p *sfParser) skipOWS() {
	for p.peek() == ' ' || p.peek() == '\t' {
		p.pos++
	}
}

func (p *sfParser) peek() byte {
	if p.pos >= len(p.input) {
		return 0
	}
	return p.input[p.pos]
}

func (p *sfParser) consume(want byte) bool {
	if p.peek() != want {
		return false
	}
	p.pos++
	return true
}

func validSFTokenRest(b byte) bool {
	return isAlpha(b) || isDigit(b) || strings.ContainsRune("!#$%&'*+-.^_`|~:/", rune(b))
}

func isDigit(b byte) bool { return b >= '0' && b <= '9' }

func lowerHex(b byte) (byte, bool) {
	switch {
	case b >= '0' && b <= '9':
		return b - '0', true
	case b >= 'a' && b <= 'f':
		return b - 'a' + 10, true
	default:
		return 0, false
	}
}

func parameter(params []sfParameter, key string) (sfBare, bool) {
	for _, param := range params {
		if param.key == key {
			return param.value, true
		}
	}
	return sfBare{}, false
}
