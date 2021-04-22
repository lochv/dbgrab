package dbgrab

import (
	"dbgrab/internal/dbio"
	"io/ioutil"
	"log"
	"strconv"
	"strings"
	"time"
)

type engine struct {
	ReadTimeout    time.Duration
	WriteTimeout   time.Duration
	exclude        string
	probes         []Probe
	probesMapKName map[string]Probe
	in             chan dbio.Receive
	out            chan dbio.Report
}

func (e *engine) loadProbesFromFile(filePath string) {
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		panic("Canot load " + filePath)
	}
	content := string(data)
	var probes []Probe
	var lines []string
	linesTemp := strings.Split(content, "\n")
	for _, lineTemp := range linesTemp {
		lineTemp = strings.TrimSpace(lineTemp)
		if lineTemp == "" || strings.HasPrefix(lineTemp, "#") {
			continue
		}
		lines = append(lines, lineTemp)
	}

	if len(lines) == 0 {
		panic("Failed to read nmap-service-probes file for probe data, 0 lines read.")
	}
	c := 0
	for _, line := range lines {
		if strings.HasPrefix(line, "Exclude ") {
			c += 1
		}

		if c > 1 {
			panic("Only 1 Exclude directive is allowed in the nmap-service-probes file")
		}
	}
	l := lines[0]
	if !(strings.HasPrefix(l, "Exclude ") || strings.HasPrefix(l, "Probe ")) {
		panic("Parse error on nmap-service-probes")
	}
	if c == 1 {
		e.exclude = l[len("Exclude")+1:]
		lines = lines[1:]
	}
	content = strings.Join(lines, "\n")
	content = "\n" + content

	probeParts := strings.Split(content, "\nProbe")
	probeParts = probeParts[1:]

	for _, probePart := range probeParts {
		probe := Probe{}
		err := probe.fromString(probePart)
		if err != nil {
			log.Println(err)
			continue
		}
		probes = append(probes, probe)
	}
	e.probes = probes
}

func (e *engine) parseProbesToMapKName() {
	var probesMap = map[string]Probe{}
	for _, probe := range e.probes {
		probesMap[probe.Name] = probe
	}
	e.probesMapKName = probesMap
}

func newEngine(filePath string, readTimeout time.Duration, writeTimeout time.Duration, in chan dbio.Receive, out chan dbio.Report) *engine {
	e := &engine{

		ReadTimeout:  readTimeout,
		WriteTimeout: writeTimeout,

		exclude:        "",
		probes:         nil,
		probesMapKName: nil,
		in:             in,
		out:            out,
	}
	e.loadProbesFromFile(filePath)
	e.parseProbesToMapKName()
	return e
}

func (e *engine) scan(target dbio.Receive) dbio.Report {
	var res = dbio.Report{}
	res.Host = target.Host
	res.Ip = target.Ip
	res.Port = target.Port
	var ssl = false
	var lastResponse = make([]byte, 0)
	for index := 0; index < len(e.probes); index++ {
	START:
		var response []byte
		var err error
		response, err = grabResponse(target.Ip+":"+strconv.Itoa(target.Port), e.probes[index].Data, e.ReadTimeout, e.WriteTimeout, ssl)
		if err != nil && len(response) == 0 {
			if err.Error() == "Closed" {
				//port closed or blocked
				if index == 0 {
					res.Service = "Closed"
				}
				return res
			} else {
				continue
			}
		}

		if len(response) == 0 {
			continue
		}

		lastResponse = response
		var softFound = false
		var softMatch Match

		for _, match := range *e.probes[index].Matchs {
			matched := match.MatchPattern(response)
			if matched && match.Service == "ssl" {
				//if detect ssl, rescan with ssl
				if ssl == false {
					ssl = true
					index = 0
					goto START
				}
			}
			if matched && !match.IsSoft {
				res.Service = match.Service
				if ssl {
					if res.Service[len(res.Service)-1:] != "s" {
						res.Service = res.Service + "s"
					}
				}
				res.Banner = string(lastResponse)
				//if match (hardmatch) return
				return res
			}
			if matched && match.IsSoft && !softFound {
				softFound = true
				softMatch = match
			}
		}

		//if not found any match or just soft, use fallback
		fallback := e.probes[index].Fallback
		if _, ok := e.probesMapKName[fallback]; ok {
			fbProbe := e.probesMapKName[fallback]
			for _, match := range *fbProbe.Matchs {
				matched := match.MatchPattern(response)
				if matched && match.Service == "ssl" {
					//if detect ssl, rescan with ssl
					ssl = true
					index = 0
					goto START
				}
				if matched && !match.IsSoft {
					res.Service = match.Service
					if ssl {
						if res.Service[len(res.Service)-1:] != "s" {
							res.Service = res.Service + "s"
						}
					}
					res.Banner = string(response)
					//if match (hardmatch) return
					return res
				}
				if matched && match.IsSoft && !softFound {
					softFound = true
					softMatch = match
				}
			}
		}
		if softFound {
			res.Service = softMatch.Service
			if ssl {
				if res.Service[len(res.Service)-1:] != "s" {
					res.Service = res.Service + "s"
				}
			}
			res.Banner = string(response)
			return res
		}
	}

	if ssl && res.Service == "" {
		res.Service = "ssl"
	} else if res.Service == "" {
		res.Service = "unknow"
	}
	res.Banner = string(lastResponse)
	return res
}

func (this *engine) worker() {
	go func() {
		for {
			j := <-this.in
			res := this.scan(j)
			if res.Service == "" {
				continue
			}
			if res.Banner == "" {
				continue
			}
			this.out <- res
		}
	}()
}
