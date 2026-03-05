package tasks

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/ethclient"
	fastshot "github.com/opus-domini/fast-shot"
	"github.com/paycrest/aggregator/ent"
	networkent "github.com/paycrest/aggregator/ent/network"
	"github.com/paycrest/aggregator/storage"
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
				masked := maskRPCEndpoint(n.RPCEndpoint)
				sanitizedErr := strings.ReplaceAll(err.Error(), n.RPCEndpoint, masked)
				mu.Lock()
				failures = append(failures, rpcFailure{
					network:  n.Identifier,
					endpoint: masked,
					err:      sanitizedErr,
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
	client, err := ethclient.DialContext(ctx, endpoint)
	if err != nil {
		return fmt.Errorf("dial failed: %w", err)
	}
	defer client.Close()

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
	if res.StatusCode() < 200 || res.StatusCode() >= 300 {
		return fmt.Errorf("tron RPC returned HTTP %d", res.StatusCode())
	}
	_, err = utils.ParseJSONResponse(res.RawResponse)
	if err != nil {
		return fmt.Errorf("tron RPC invalid response: %w", err)
	}
	return nil
}

// maskRPCEndpoint redacts path/query/key portions of an RPC URL for safe logging.
func maskRPCEndpoint(endpoint string) string {
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "***"
	}
	return fmt.Sprintf("%s://%s/***", u.Scheme, u.Host)
}
