package otlp

import (
	"testing"

	"github.com/exitCodeNihil/qafas-sandbox/controlplane/internal/store"
)

func TestDestinationLangfuse(t *testing.T) {
	url, headers, err := destination(store.ObservabilitySettings{
		Provider: "langfuse", Host: "https://cloud.langfuse.com/", PublicKey: "pk", SecretKey: "sk",
	})
	if err != nil {
		t.Fatalf("destination: %v", err)
	}
	if url != "https://cloud.langfuse.com/api/public/otel/v1/traces" {
		t.Fatalf("url: %q", url)
	}
	auth := headers["Authorization"]
	if auth != "Basic cGs6c2s=" { // base64("pk:sk")
		t.Fatalf("auth header: %q", auth)
	}
}

func TestDestinationLangfuseMissingCreds(t *testing.T) {
	if _, _, err := destination(store.ObservabilitySettings{Provider: "langfuse", Host: "https://x"}); err == nil {
		t.Fatal("want error for missing public_key/secret_key")
	}
}

func TestDestinationOtlp(t *testing.T) {
	url, headers, err := destination(store.ObservabilitySettings{
		Provider: "otlp", OTLPURL: "http://collector:4318/v1/traces", OTLPHeaders: map[string]string{"X-Api-Key": "z"},
	})
	if err != nil {
		t.Fatalf("destination: %v", err)
	}
	if url != "http://collector:4318/v1/traces" || headers["X-Api-Key"] != "z" {
		t.Fatalf("url/headers: %q %+v", url, headers)
	}
}

func TestDestinationOtlpMissingURL(t *testing.T) {
	if _, _, err := destination(store.ObservabilitySettings{Provider: "otlp"}); err == nil {
		t.Fatal("want error for missing otlp_url")
	}
}

func TestHasAlert(t *testing.T) {
	if hasAlert(store.AlertCounts{}) {
		t.Fatal("zero counts must not count as an alert")
	}
	if !hasAlert(store.AlertCounts{Low: 1}) {
		t.Fatal("a single low alert still counts")
	}
}
