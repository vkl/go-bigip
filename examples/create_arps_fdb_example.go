package main

import (
	"fmt"
	"io/ioutil"
	log "github.com/F5Networks/k8s-bigip-ctlr/pkg/vlogger"
	clog "github.com/F5Networks/k8s-bigip-ctlr/pkg/vlogger/console"
	"os"
	"github.com/f5devcentral/go-bigip"
)

func initLogger(logLevel string) error {
	log.RegisterLogger(
		log.LL_MIN_LEVEL, log.LL_MAX_LEVEL, clog.NewConsoleLogger())

	if ll := log.NewLogLevel(logLevel); nil != ll {
		log.SetLogLevel(*ll)
	} else {
		return fmt.Errorf("Unknown log level requested: %s\n"+
			"    Valid log levels are: DEBUG, INFO, WARNING, ERROR, CRITICAL", logLevel)
	}
	return nil
}

func main() {
	os.Setenv("BIGIP_HOST", "10.145.67.133")
	os.Setenv("BIGIP_USER", "admin")
	os.Setenv("BIGIP_PASSWORD", "F5site02")
	os.Setenv("LOG_LEVEL", "DEBUG")
	Loglevel := os.Getenv("LOG_LEVEL")
	initLogger(Loglevel)
	data, err := ioutil.ReadFile("net-service.json")
	if err != nil {
		log.Errorf("Json reading Failed with :%v", err)
		return
	}
	log.Debugf("Contents of file:", string(data))
	netobject, err := bigip.CreateNetObject(string(data))
	if err != nil {
		log.Errorf("Netobject creation failed with:%v", err)
		return
	}
	log.Infof("Structure of CCLNET::%v", netobject)
	err = netobject.F5CloudserviceManager()
	if err != nil {
		log.Errorf("Connection to BIGIP failed with:%v", err)
		return
	}
}
