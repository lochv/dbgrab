package dbgrab

import (
	"dbgrab/internal/dbio"
	"time"
)

type dbgrab struct {
	kill chan int
	*engine
}

func New(filePath string, in chan dbio.Receive, out chan dbio.Report) *dbgrab {
	return &dbgrab{
		engine: newEngine(filePath, 5*time.Second, 2*time.Second, in, out),
		kill:   make(chan int),
	}
}

func (this *dbgrab) Run(worker int) {
	go func() {
		for i := 0; i < worker; i++ {
			this.worker()
		}
	}()
}

func (this *dbgrab) Wait() {
	<-this.kill
}
