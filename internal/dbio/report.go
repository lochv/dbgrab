package dbio

import (
	"dbgrab/internal/config"
	"encoding/json"
	"fmt"
	"os"
)

type Report struct {
	Host    string `json:"host"`
	Ip      string `json:"ip"`
	Port    int    `json:"port"`
	Service string `json:"service"`
	Banner  string `json:"banner,omitempty"`
}

func NewRp() chan Report {
	in := make(chan Report, 32)
	switch config.Conf.ReportMode {
	case "console":
		go func() {
			for {
				mess := <-in
				fmt.Printf("\nHost %s:%d | %s", mess.Host, mess.Port, mess.Service)
			}
		}()
	case "remote":
	//todo impl
	case "file":
		go func() {
			for {
				mess := <-in
				f, err := os.OpenFile(config.Conf.OutputFile, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
				if err != nil {
					continue
				}
				bytes, _ := json.Marshal(mess)
				f.WriteString("\n")
				f.Write(bytes)
				f.Close()
			}
		}()
	}
	return in
}
