package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/rainchen537/dnsgo/agent"
	"github.com/rainchen537/dnsgo/deploy"
	"github.com/rainchen537/dnsgo/providers"
)

func main() {
	if err := execute(); err != nil {
		log.Fatal(err)
	}
}

func execute() error {
	if len(os.Args) < 2 {
		return usage()
	}
	switch os.Args[1] {
	case "providers":
		fmt.Println(strings.Join(providers.Names(), "\n"))
		return nil
	case "deploy-targets":
		fmt.Println(strings.Join(deploy.Names(), "\n"))
		return nil
	case "check", "once", "run":
	case "inspect-cert", "resolve-cert":
		if (os.Args[1] == "inspect-cert" && len(os.Args) != 6) ||
			(os.Args[1] == "resolve-cert" && len(os.Args) != 8 && len(os.Args) != 12) ||
			os.Args[2] != "-database" || os.Args[4] != "-id" {
			return usage()
		}
		store, err := agent.OpenStore(os.Args[3])
		if err != nil {
			return err
		}
		defer store.Close()
		if os.Args[1] == "resolve-cert" {
			if os.Args[6] != "-action" {
				return usage()
			}
			var details []string
			if len(os.Args) == 12 {
				if os.Args[7] != "mark-deployed" || os.Args[8] != "-location" || os.Args[10] != "-target" {
					return usage()
				}
				details = []string{os.Args[9], os.Args[11]}
			}
			unlock, err := store.AcquireRunnerLock()
			if err != nil {
				return err
			}
			defer unlock()
			return store.ResolveCertificate(context.Background(), os.Args[5], os.Args[7], details...)
		}
		summary, err := store.CertificateSummary(context.Background(), os.Args[5])
		if err != nil {
			return err
		}
		encoded, err := json.MarshalIndent(summary, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(encoded))
		return nil
	case "inspect-schedule":
		if len(os.Args) != 6 || os.Args[2] != "-database" || os.Args[4] != "-id" {
			return usage()
		}
		store, err := agent.OpenStore(os.Args[3])
		if err != nil {
			return err
		}
		defer store.Close()
		summary, err := store.ScheduleSummary(context.Background(), os.Args[5])
		if err != nil {
			return err
		}
		encoded, err := json.MarshalIndent(summary, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(encoded))
		return nil
	case "inspect-failover", "resolve-failover":
		if (os.Args[1] == "inspect-failover" && len(os.Args) != 6) ||
			(os.Args[1] == "resolve-failover" && len(os.Args) != 8 && len(os.Args) != 10) ||
			os.Args[2] != "-database" || os.Args[4] != "-id" {
			return usage()
		}
		store, err := agent.OpenStore(os.Args[3])
		if err != nil {
			return err
		}
		defer store.Close()
		if os.Args[1] == "resolve-failover" {
			if os.Args[6] != "-action" {
				return usage()
			}
			recordID := ""
			if len(os.Args) == 10 {
				if os.Args[8] != "-record-id" || os.Args[7] != "mark-done" {
					return usage()
				}
				recordID = os.Args[9]
			}
			unlock, err := store.AcquireRunnerLock()
			if err != nil {
				return err
			}
			defer unlock()
			return store.ResolveFailover(context.Background(), os.Args[5], os.Args[7], recordID, time.Now())
		}
		summary, err := store.FailoverSummary(context.Background(), os.Args[5])
		if err != nil {
			return err
		}
		encoded, err := json.MarshalIndent(summary, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(encoded))
		return nil
	case "resolve-schedule":
		if (len(os.Args) != 8 && len(os.Args) != 10) || os.Args[2] != "-config" ||
			os.Args[4] != "-id" || os.Args[6] != "-action" {
			return usage()
		}
		recordID := ""
		if len(os.Args) == 10 {
			if os.Args[8] != "-record-id" {
				return usage()
			}
			recordID = os.Args[9]
		}
		config, err := agent.LoadConfig(os.Args[3])
		if err != nil {
			return err
		}
		var task *agent.ScheduleConfig
		for index := range config.Schedules {
			if config.Schedules[index].ID == os.Args[5] {
				task = &config.Schedules[index]
				break
			}
		}
		if task == nil {
			return fmt.Errorf("schedule %s is absent from configuration", os.Args[5])
		}
		store, err := agent.OpenStore(config.Database)
		if err != nil {
			return err
		}
		defer store.Close()
		unlock, err := store.AcquireRunnerLock()
		if err != nil {
			return err
		}
		defer unlock()
		return store.ResolveSchedule(context.Background(), *task, os.Args[7], recordID, time.Now())
	default:
		return usage()
	}
	if len(os.Args) != 4 || os.Args[2] != "-config" {
		return usage()
	}
	config, err := agent.LoadConfig(os.Args[3])
	if err != nil {
		return err
	}
	if os.Args[1] == "check" {
		directory, err := os.MkdirTemp("", "dnsgo-check-")
		if err != nil {
			return err
		}
		defer os.RemoveAll(directory)
		store, err := agent.OpenStore(filepath.Join(directory, "state.db"))
		if err != nil {
			return err
		}
		defer store.Close()
		if _, err := agent.NewRunner(config, store); err != nil {
			return err
		}
		fmt.Println("配置结构有效；未连接厂商或执行任务")
		return nil
	}
	store, err := agent.OpenStore(config.Database)
	if err != nil {
		return err
	}
	defer store.Close()
	unlock, err := store.AcquireRunnerLock()
	if err != nil {
		return err
	}
	defer unlock()
	runner, err := agent.NewRunner(config, store)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if os.Args[1] == "once" {
		if err := runner.Tick(ctx); err != nil {
			return fmt.Errorf("task tick: %s", agent.SafeError(err))
		}
		return nil
	}
	runner.OnError = func(err error) { log.Printf("task tick: %s", agent.SafeError(err)) }
	return runner.Run(ctx)
}

func usage() error {
	return fmt.Errorf("usage: dnsgo-agent {providers|deploy-targets|check -config FILE|once -config FILE|run -config FILE|inspect-cert -database FILE -id ID|resolve-cert -database FILE -id ID -action retry|resume-order|mark-validating|resume-issued|mark-deployed [-location ID -target TARGET]|inspect-failover -database FILE -id ID|resolve-failover -database FILE -id ID -action retry|mark-done [-record-id ID]|inspect-schedule -database FILE -id ID|resolve-schedule -config FILE -id ID -action retry|mark-done [-record-id ID]}")
}
