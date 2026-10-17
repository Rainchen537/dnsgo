package providers

import (
	"errors"
	"net/http"
	"testing"

	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"github.com/rainchen537/dnsgo"
)

func TestAWSWriteErrorRequiresReadbackWhenOutcomeIsUnknown(t *testing.T) {
	serverFailure := &smithyhttp.ResponseError{Response: &smithyhttp.Response{Response: &http.Response{StatusCode: 500}},
		Err: &smithy.GenericAPIError{Code: "InternalFailure", Message: "server error"}}
	for _, operation := range []string{"create_zone", "change_record_sets"} {
		if err := awsError(operation, serverFailure); !dnsgo.IsCode(err, dnsgo.CodeResultUnknown) {
			t.Errorf("%s HTTP 500 was classified as safe to retry: %v", operation, err)
		}
		if err := awsError(operation, errors.New("connection lost")); !dnsgo.IsCode(err, dnsgo.CodeResultUnknown) {
			t.Errorf("%s transport loss was classified as safe to retry: %v", operation, err)
		}
	}
	invalid := &smithyhttp.ResponseError{Response: &smithyhttp.Response{Response: &http.Response{StatusCode: 400}},
		Err: &smithy.GenericAPIError{Code: "InvalidChangeBatch", Message: "invalid batch"}}
	if err := awsError("change_record_sets", invalid); !dnsgo.IsCode(err, dnsgo.CodeConflict) {
		t.Errorf("explicit Route 53 rejection was not preserved: %v", err)
	}
}
