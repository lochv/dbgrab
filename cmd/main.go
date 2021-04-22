package main

import (
	"dbgrab"
	"dbgrab/internal/config"
	"dbgrab/internal/dbio"
)

func main() {
	recvChan := dbio.NewRecv()
	rpChan := dbio.NewRp()
	db := dbgrab.New("./nmap-service-probes", recvChan, rpChan)
	db.Run(config.Conf.Workers)
	db.Wait()
}
