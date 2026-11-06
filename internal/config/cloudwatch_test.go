package config

import (
	"strings"
	"testing"
)

func TestCloudWatchValidation(t *testing.T) {
	const block = "cloudwatch: { region: eu-west-1, db_instance_id: example-db }"
	for _, tc := range []struct{ name, repl, want string }{
		{"region with a path", "cloudwatch: { region: \"evil.example.com/x\", db_instance_id: example-db }", "not an AWS region name"},
		{"region in capitals", "cloudwatch: { region: EU-WEST-1, db_instance_id: example-db }", "not an AWS region name"},
		{"instance id with a space", "cloudwatch: { region: eu-west-1, db_instance_id: \"my db\" }", "RDS instance identifier"},
		{"instance id starting with a digit", "cloudwatch: { region: eu-west-1, db_instance_id: 1db }", "RDS instance identifier"},
	} {
		_, _, err := Parse([]byte(strings.Replace(validYAML, block, tc.repl, 1)))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v", tc.name, err)
		}
	}
	for _, region := range []string{"eu-west-1", "us-gov-west-1", "ap-southeast-2", "cn-north-1", "me-central-1"} {
		y := strings.Replace(validYAML, block, "cloudwatch: { region: "+region+", db_instance_id: example-db }", 1)
		if _, _, err := Parse([]byte(y)); err != nil {
			t.Errorf("region %s rejected: %v", region, err)
		}
	}
}
