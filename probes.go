package dbgrab

import (
	"dbgrab/internal/pcre"
	"fmt"
	"strings"
)

//parse nmap 's probes

type Match struct {
	IsSoft          bool
	Service         string
	Pattern         string
	VersionInfo     string
	PatternCompiled *pcre.Regexp
}

func (m *Match) MatchPattern(response []byte) bool {
	return m.PatternCompiled.Match(response, 0)
}

type Probe struct {
	Name     string
	Data     []byte
	Protocol string
	Fallback string
	Matchs   *[]Match
}

type Directive struct {
	DirectiveName string
	Flag          string
	Delimiter     string
	DirectiveStr  string
}

func (p *Probe) getDirectiveSyntax(data string) (directive Directive) {
	directive = Directive{}

	if strings.Count(data, " ") <= 0 {
		fmt.Println(data)
		panic("nmap-service-probes - error directive format")
	}
	blankIndex := strings.Index(data, " ")
	directiveName := data[:blankIndex]
	Flag := data[blankIndex+1 : blankIndex+2]
	delimiter := data[blankIndex+2 : blankIndex+3]
	directiveStr := data[blankIndex+3:]

	directive.DirectiveName = directiveName
	directive.Flag = Flag
	directive.Delimiter = delimiter
	directive.DirectiveStr = directiveStr

	return directive
}

func (p *Probe) getMatch(data string) (match Match, err *pcre.CompileError) {
	match = Match{}

	matchText := data[len("match")+1:]
	directive := p.getDirectiveSyntax(matchText)

	textSplited := strings.Split(directive.DirectiveStr, directive.Delimiter)

	pattern, versionInfo := textSplited[0], strings.Join(textSplited[1:], "")

	patternCompiled, err := pcre.Compile(pattern, pcre.DOTALL|pcre.CASELESS)
	if err != nil {
		return match, err
	}

	match.Service = directive.DirectiveName
	match.Pattern = pattern
	match.PatternCompiled = &patternCompiled
	match.VersionInfo = versionInfo

	return match, nil
}

func (p *Probe) getSoftMatch(data string) (softMatch Match, err error) {
	softMatch = Match{IsSoft: true}

	matchText := data[len("softmatch")+1:]
	directive := p.getDirectiveSyntax(matchText)
	textSplited := strings.Split(directive.DirectiveStr, directive.Delimiter)
	pattern, versionInfo := textSplited[0], strings.Join(textSplited[1:], "")
	patternCompiled, err1 := pcre.Compile(pattern, pcre.DOTALL|pcre.CASELESS)
	if err1 != nil {
		fmt.Println("Parse softmatch data failed, data:", data)
		return softMatch, err
	}
	softMatch.Service = directive.DirectiveName
	softMatch.Pattern = pattern
	softMatch.PatternCompiled = &patternCompiled
	softMatch.VersionInfo = versionInfo

	return softMatch, nil
}

func (p *Probe) parseFallback(data string) {
	p.Fallback = data[len("fallback")+1:]
}

func (p *Probe) fromString(data string) error {
	var err error

	data = strings.TrimSpace(data)
	lines := strings.Split(data, "\n")
	probeStr := lines[0]

	p.parseProbeInfo(probeStr)

	var matchs []Match
	for _, line := range lines {
		if strings.HasPrefix(line, "match ") {
			match, err := p.getMatch(line)
			if err != nil {
				continue
			}
			matchs = append(matchs, match)
		} else if strings.HasPrefix(line, "softmatch ") {
			softMatch, err := p.getSoftMatch(line)
			if err != nil {
				continue
			}
			matchs = append(matchs, softMatch)
		} else if strings.HasPrefix(line, "fallback ") {
			p.parseFallback(line)
		}
	}
	p.Matchs = &matchs
	return err
}

func (p *Probe) parseProbeInfo(probeStr string) {
	proto := probeStr[:4]
	other := probeStr[4:]

	if !(proto == "TCP " || proto == "UDP ") {
		return
	}
	if len(other) == 0 {
		return
	}

	directive := p.getDirectiveSyntax(other)
	p.Name = directive.DirectiveName
	p.Data, _ = DecodeData(strings.Split(directive.DirectiveStr, directive.Delimiter)[0])
	p.Protocol = strings.ToLower(strings.TrimSpace(proto))
}
