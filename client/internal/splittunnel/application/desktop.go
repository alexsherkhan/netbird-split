package application

import (
	"bufio"
	"bytes"
	"strconv"
	"strings"
)

const (
	desktopEntryGroup = "Desktop Entry"
	maxDesktopLine    = 64 * 1024
)

type entryStatus int

const (
	entrySkipped entryStatus = iota
	entryHidden
	entryOK
)

func parseDesktopEntry(data []byte, source Source, sourcePath, desktopID string) (Application, entryStatus) {
	fields, ok := parseDesktopFields(data)
	if !ok {
		return Application{}, entrySkipped
	}
	if fields["Type"] != "Application" {
		return Application{}, entrySkipped
	}
	name := unescapeDesktopValue(fields["Name"])
	if name == "" {
		return Application{}, entrySkipped
	}
	if desktopBool(fields["Hidden"]) {
		return Application{}, entryHidden
	}

	executable, _ := parseExec(fields["Exec"])
	app := Application{
		DesktopID:   desktopID,
		Name:        name,
		Icon:        parseIcon(fields["Icon"]),
		Executable:  executable,
		InstallType: source.InstallType,
		SourcePath:  sourcePath,
		NoDisplay:   desktopBool(fields["NoDisplay"]),
	}
	return app, entryOK
}

func parseDesktopFields(data []byte) (map[string]string, bool) {
	fields := make(map[string]string)
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 4096), maxDesktopLine)

	inEntry := false
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			inEntry = line == "["+desktopEntryGroup+"]"
			continue
		}
		if !inEntry {
			continue
		}
		key, value, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		key = strings.TrimSpace(key)
		if key == "" || isLocalizedKey(key) {
			continue
		}
		fields[key] = strings.TrimSpace(value)
	}
	if err := scanner.Err(); err != nil {
		return nil, false
	}
	return fields, true
}

func isLocalizedKey(key string) bool {
	open := strings.IndexByte(key, '[')
	return open > 0 && strings.HasSuffix(key, "]")
}

func parseIcon(value string) Icon {
	value = strings.TrimSpace(unescapeDesktopValue(value))
	if value == "" {
		return Icon{}
	}
	if strings.HasPrefix(value, "/") {
		return Icon{Path: value}
	}
	return Icon{Name: value}
}

func desktopBool(value string) bool {
	result, err := strconv.ParseBool(strings.TrimSpace(unescapeDesktopValue(value)))
	return err == nil && result
}

func unescapeDesktopValue(value string) string {
	if !strings.ContainsRune(value, '\\') {
		return value
	}
	var b strings.Builder
	b.Grow(len(value))
	for i := 0; i < len(value); i++ {
		if value[i] != '\\' || i+1 >= len(value) {
			b.WriteByte(value[i])
			continue
		}
		i++
		switch value[i] {
		case 's':
			b.WriteByte(' ')
		case 'n':
			b.WriteByte('\n')
		case 't':
			b.WriteByte('\t')
		case 'r':
			b.WriteByte('\r')
		case '\\':
			b.WriteByte('\\')
		default:
			b.WriteByte(value[i])
		}
	}
	return b.String()
}

func parseExec(value string) (string, []string) {
	tokens := splitExec(value)
	cleaned := make([]string, 0, len(tokens))
	for _, token := range tokens {
		token = stripFieldCodes(token)
		if token != "" {
			cleaned = append(cleaned, token)
		}
	}
	if len(cleaned) == 0 {
		return "", nil
	}
	return cleaned[0], cleaned[1:]
}

func splitExec(value string) []string {
	var (
		tokens  []string
		current strings.Builder
		inQuote bool
		started bool
	)
	for i := 0; i < len(value); i++ {
		c := value[i]
		switch {
		case c == '\\' && i+1 < len(value):
			i++
			switch value[i] {
			case 's':
				current.WriteByte(' ')
			case 'n':
				current.WriteByte('\n')
			case 't':
				current.WriteByte('\t')
			case 'r':
				current.WriteByte('\r')
			default:
				current.WriteByte(value[i])
			}
			started = true
		case c == '"':
			inQuote = !inQuote
			started = true
		case !inQuote && (c == ' ' || c == '\t'):
			if started {
				tokens = append(tokens, current.String())
				current.Reset()
				started = false
			}
		default:
			current.WriteByte(c)
			started = true
		}
	}
	if started {
		tokens = append(tokens, current.String())
	}
	return tokens
}

func stripFieldCodes(value string) string {
	if !strings.ContainsRune(value, '%') {
		return value
	}
	var b strings.Builder
	b.Grow(len(value))
	for i := 0; i < len(value); i++ {
		if value[i] != '%' {
			b.WriteByte(value[i])
			continue
		}
		if i+1 < len(value) && value[i+1] == '%' {
			b.WriteByte('%')
			i++
			continue
		}
		if i+1 < len(value) {
			i++
		}
	}
	return b.String()
}
