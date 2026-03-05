package tasks

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	fastshot "github.com/opus-domini/fast-shot"
	"github.com/paycrest/aggregator/ent"
	networkent "github.com/paycrest/aggregator/ent/network"
	"github.com/paycrest/aggregator/storage"
	"github.com/paycrest/aggregator/types"
	"github.com/paycrest/aggregator/utils"
	"github.com/paycrest/aggregator/utils/logger"
)

// TaskCheckRPCHealth checks all configured RPC endpoints and logs errors for any that are unreachable.
// Errors are reported to GlitchTip via the Sentry logger hook, which triggers Slack alerts.
func TaskCheckRPCHealth() error {
	ctx := context.Background()

	cleanup, acquired, err := acquireDistributedLock(ctx, "task_check_rpc_health_lock", 30*time.Second, "TaskCheckRPCHealth")
	if err != nil {
		return err
	}
	if !acquired {
		return nil
	}
	defer cleanup()

	isTestnet := serverConf.Environment != "production" && serverConf.Environment != "staging"

	networks, err := storage.Client.Network.
		Query().
		Where(networkent.IsTestnetEQ(isTestnet)).
		All(ctx)
	if err != nil {
		return fmt.Errorf("TaskCheckRPCHealth.fetchNetworks: %w", err)
	}

	type rpcFailure struct {
		network  string
		endpoint string
		err      string
	}

	var (
		mu       sync.Mutex
		failures []rpcFailure
		wg       sync.WaitGroup
	)

	for _, network := range networks {
		wg.Add(1)
		go func(n *ent.Network) {
			defer wg.Done()

			checkCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
			defer cancel()

			if err := checkRPCEndpoint(checkCtx, n); err != nil {
				mu.Lock()
				failures = append(failures, rpcFailure{
					network:  n.Identifier,
					endpoint: maskRPCEndpoint(n.RPCEndpoint),
					err:      err.Error(),
				})
				mu.Unlock()
			}
		}(network)
	}

	wg.Wait()

	for _, f := range failures {
		logger.WithFields(logger.Fields{
			"Network":     f.network,
			"RPCEndpoint": f.endpoint,
		}).Errorf("RPC health check failed: %s", f.err)
	}

	return nil
}

func checkRPCEndpoint(ctx context.Context, network *ent.Network) error {
	if strings.HasPrefix(network.Identifier, "tron") {
		return checkTronRPC(network.RPCEndpoint)
	}
	return checkEVMRPC(ctx, network.RPCEndpoint)
}

func checkEVMRPC(ctx context.Context, endpoint string) error {
	client, err := types.NewEthClient(endpoint)
	if err != nil {
		return fmt.Errorf("dial failed: %w", err)
	}
	_, err = client.HeaderByNumber(ctx, nil)
	if err != nil {
		return fmt.Errorf("eth_getBlockByNumber failed: %w", err)
	}
	return nil
}

func checkTronRPC(endpoint string) error {
	res, err := fastshot.NewClient(endpoint).
		Config().SetTimeout(15 * time.Second).
		Build().POST("/wallet/getblockbylatestnum").
		Body().AsJSON(map[string]interface{}{"num": 1}).
		Send()
	if err != nil {
		return fmt.Errorf("tron RPC request failed: %w", err)
	}
	_, err = utils.ParseJSONResponse(res.RawResponse)
	if err != nil {
		return fmt.Errorf("tron RPC invalid response: %w", err)
	}
	return nil
}

// maskRPCEndpoint redacts path/key portions of an RPC URL for safe logging.
func maskRPCEndpoint(endpoint string) string {
	parts := strings.SplitN(endpoint, "//", 2)
	if len(parts) != 2 {
		return "***"
	}
	rest := parts[1]
	slashIdx := strings.Index(rest, "/")
	if slashIdx == -1 {
		return endpoint
	}
	return fmt.Sprintf("%s//%s/***", parts[0], rest[:slashIdx])
}
