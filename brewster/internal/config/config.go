package config

// AuditConfig holds configuration for local audits
type AuditConfig struct {
	CheckCVE       bool
	CheckAbandoned bool
	CheckHTTP      bool
	Verbose        bool
}
