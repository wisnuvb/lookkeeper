package cloudwatch

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/config"
	cw "github.com/aws/aws-sdk-go-v2/service/cloudwatch"
)

// sdkTimeout bounds each HTTP request made by the SDK. The collector additionally
// bounds a whole GetMetricData call, retries included, with Options.CallTimeout.
const sdkTimeout = 10 * time.Second

// NewSDK returns an API backed by the real AWS SDK client for region.
//
// Nothing happens until the first call: the client is built lazily, so loading a
// configuration, `config validate` and every test stay free of AWS. Credentials
// are resolved by the standard AWS chain (environment variables, shared
// config/credentials files and profiles, SSO, container or instance roles); this
// package takes no credential parameter and stores none. SDK request logging is
// off (the default), so requests and signatures are never logged.
func NewSDK(region string) API { return &lazyClient{region: region} }

type lazyClient struct {
	region string
	// extra options, set only by tests (loopback HTTP client, endpoint override).
	loadOpts   []func(*config.LoadOptions) error
	clientOpts []func(*cw.Options)

	mu     sync.Mutex
	client *cw.Client
}

func (l *lazyClient) get(ctx context.Context) (*cw.Client, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.client != nil {
		return l.client, nil
	}
	opts := append([]func(*config.LoadOptions) error{
		config.WithRegion(l.region),
		config.WithRetryMode(aws.RetryModeStandard),
		config.WithRetryMaxAttempts(3),
		config.WithHTTPClient(awshttp.NewBuildableClient().WithTimeout(sdkTimeout)),
	}, l.loadOpts...)
	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		// Do not wrap err: it may quote file contents or profile settings.
		return nil, errors.New("load AWS configuration (check AWS_PROFILE, AWS_CONFIG_FILE and the shared config files)")
	}
	l.client = cw.NewFromConfig(cfg, l.clientOpts...)
	return l.client, nil
}

// GetMetricData implements API.
func (l *lazyClient) GetMetricData(ctx context.Context, in *cw.GetMetricDataInput, optFns ...func(*cw.Options)) (*cw.GetMetricDataOutput, error) {
	c, err := l.get(ctx)
	if err != nil {
		return nil, err
	}
	return c.GetMetricData(ctx, in, optFns...)
}
