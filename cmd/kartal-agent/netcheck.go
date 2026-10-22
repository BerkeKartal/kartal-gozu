package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/BerkeKartal/kartal-gozu/internal/netcheck"
)

// netCheck is what a network check's pod runs: it tries each host:port of
// args and prints the results as one JSON line, which the agent reads from
// the pod's log.
func netCheck(args []string) int {
	targets, err := netcheck.ParseTargets(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	b, err := json.Marshal(netcheck.Run(ctx, nil, targets))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Println(string(b))
	return 0
}
