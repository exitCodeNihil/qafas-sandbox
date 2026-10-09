package config

import "testing"

func TestTLSCertAndKeyGoTogether(t *testing.T) {
	if _, err := Load([]string{"-tls-cert", "c.pem"}); err == nil {
		t.Fatal("a cert without a key must be refused")
	}
	if _, err := Load([]string{"-tls-key", "k.pem"}); err == nil {
		t.Fatal("a key without a cert must be refused")
	}
	cfg, err := Load([]string{"-tls-cert", "c.pem", "-tls-key", "k.pem"})
	if err != nil || cfg.TLSCert != "c.pem" || cfg.TLSKey != "k.pem" {
		t.Fatalf("both set: %v %+v", err, cfg)
	}
}
