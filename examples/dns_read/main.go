// dns_read shows how another Go program can locate and inspect one DNS name.
// It only reads Cloudflare data; credentials come from the process environment.
package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/rainchen537/dnsgo"
	"github.com/rainchen537/dnsgo/providers"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) != 3 {
		return fmt.Errorf("usage: dns_read ZONE HOST")
	}
	token := os.Getenv("CLOUDFLARE_API_TOKEN")
	if token == "" {
		return fmt.Errorf("CLOUDFLARE_API_TOKEN is required")
	}
	provider, err := providers.New("cloudflare", dnsgo.Config{Credentials: map[string]string{"token": token}})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	zone, err := dnsgo.FindZone(ctx, provider, os.Args[1])
	if err != nil {
		return err
	}
	page, err := dnsgo.ListSubdomainRecords(ctx, provider, zone, os.Args[2], dnsgo.SubdomainQuery{PageSize: 10000})
	if err != nil {
		return err
	}
	if page.Total > len(page.Items) {
		return fmt.Errorf("more than 10000 records match this name; query them in smaller pages")
	}
	for _, record := range page.Items {
		name, err := dnsgo.RecordFQDN(zone, record)
		if err != nil {
			return err
		}
		fmt.Printf("%s\t%s\t%s\t%s\tTTL=%d\n", record.ID, name, record.Type, record.Value, record.TTL)
	}
	return nil
}
