package pg

import (
	"fmt"
	"time"

	"github.com/wisnuvb/lockkeeper/internal/config"
	"github.com/wisnuvb/lockkeeper/internal/preflight"
)

// checkConnectivity reports whether Lockkeeper could connect to a server and
// whether that session is encrypted. role is "source" or "target".
func checkConnectivity(role string, s Side) []preflight.Finding {
	id := "connect." + role
	if s.Server == nil {
		return []preflight.Finding{finding(id, areaConnectivity, preflight.Blocker,
			fmt.Sprintf("cannot connect from this machine to the %s %q (%s): %s", role, s.Name, s.Endpoint.Address(), s.ConnectError),
			"Check the host, port, user and password reference in the Lockkeeper config, that a firewall or security group admits this machine, and the TLS settings (verify-full needs the server's CA file in tls.ca_file). To test by hand from this machine: "+s.Endpoint.PsqlCommand())}
	}
	out := []preflight.Finding{finding(id, areaConnectivity, preflight.OK,
		fmt.Sprintf("connected to the %s %q (%s) as role %q in %s; PostgreSQL %s", role, s.Name, s.Endpoint.Address(), s.Server.Session.User,
			s.ConnectLatency.Round(time.Millisecond), s.Server.Version), "")}
	return append(out, checkTLS(role, s))
}

// checkTLS judges the encryption of the session Lockkeeper used (pg_stat_ssl for
// its own backend). Loopback and unix sockets are exempt (ADR 0004).
func checkTLS(role string, s Side) preflight.Finding {
	id := "tls." + role
	local := s.Endpoint.Local()
	mode := s.Endpoint.TLSMode
	if mode == "" {
		mode = config.TLSVerifyFull
	}
	switch {
	case s.Facts.SSL == nil:
		sev := preflight.Info
		if !local {
			sev = preflight.Warn
		}
		return finding(id, areaConnectivity, sev,
			fmt.Sprintf("could not determine whether the session to the %s is encrypted (pg_stat_ssl was not readable)", role),
			"Confirm the connection uses TLS: run `SELECT ssl, version FROM pg_stat_ssl WHERE pid = pg_backend_pid();` over the same connection settings.")
	case s.Facts.SSL.Enabled && (local || mode == config.TLSVerifyFull):
		return finding(id, areaConnectivity, preflight.OK,
			fmt.Sprintf("the session to the %s is encrypted (%s)", role, s.Facts.SSL.Version), "")
	case s.Facts.SSL.Enabled:
		return finding(id, areaConnectivity, preflight.Warn,
			fmt.Sprintf("the session to the %s is encrypted (%s) but the server's identity is not fully verified (tls mode %q)", role, s.Facts.SSL.Version, mode),
			"Set tls.mode: verify-full with the CA bundle in tls.ca_file for this connection (for RDS, the regional RDS CA bundle). `require` and `verify-ca` do not stop an impersonator with a valid certificate for another host.")
	case local:
		return finding(id, areaConnectivity, preflight.Info,
			fmt.Sprintf("the session to the %s is not encrypted; this is a loopback or unix-socket connection, which is exempt", role), "")
	default:
		return finding(id, areaConnectivity, preflight.Warn,
			fmt.Sprintf("the session to the %s %q is NOT encrypted although it is a remote host; credentials and data cross the network in clear text", role, s.Name),
			"Enable TLS on the server (RDS: it is on by default; self-hosted: ssl = on with a certificate), then set tls.mode: verify-full and tls.ca_file for this connection and remove allow_insecure.")
	}
}

// checkTargetToSource is always a WARN: the target server (not Lockkeeper) opens
// the subscription connection to the source, and testing that would need a write
// on the target (dblink or a throwaway subscription). It is reported as
// unverifiable together with the manual command.
func checkTargetToSource(in Input) []preflight.Finding {
	src := in.Source.Endpoint
	hint := ""
	if src.Local() {
		hint = " The host above is the address Lockkeeper uses; it is loopback here, so use the address by which the TARGET server can reach the source."
	}
	return []preflight.Finding{finding("network.target_to_source", areaNetwork, preflight.Warn,
		fmt.Sprintf("cannot be verified read-only: the target server %q must open a connection to the source %s, and testing that would need to create something on the target (dblink or a subscription).%s",
			in.Target.Name, src.Address(), hint),
		"From the TARGET host (not from this machine) run: "+src.PsqlCommand()+
			" (psql asks for the password; add sslrootcert=<CA bundle> if the CA is not in the system store). It must connect over TLS and print 1. "+
			"On RDS the security group of the source must allow the target's public IP on the database port.")}
}

// checkVersions compares major versions and refuses standbys.
func checkVersions(in Input) []preflight.Finding {
	src, tgt := in.Source.Server, in.Target.Server
	var out []preflight.Finding
	if src != nil && tgt != nil {
		switch {
		case tgt.Major < src.Major:
			out = append(out, finding("version.order", areaVersions, preflight.Blocker,
				fmt.Sprintf("the target runs PostgreSQL %d, older than the source's %d; logical replication works across versions only towards the same or a newer major version", tgt.Major, src.Major),
				fmt.Sprintf("Install PostgreSQL %d or newer on the target (a downgrade is not supported), or choose a different target.", src.Major)))
		case tgt.Major == src.Major:
			out = append(out, finding("version.order", areaVersions, preflight.OK,
				fmt.Sprintf("source and target both run PostgreSQL %d", src.Major), ""))
		default:
			out = append(out, finding("version.order", areaVersions, preflight.Info,
				fmt.Sprintf("the target (PostgreSQL %d) is newer than the source (%d); logical replication supports this direction. Test the application against the newer version before cutover", tgt.Major, src.Major), ""))
		}
	}
	if src != nil && src.InRecovery {
		sev := preflight.Blocker
		if src.Major >= 16 {
			sev = preflight.Warn
		}
		out = append(out, finding("source.recovery", areaSourceParams, sev,
			fmt.Sprintf("the source %q is a standby (in recovery); before PostgreSQL 16 a standby cannot host a logical slot, and from 16 on slot creation on a standby waits for the primary's activity", in.Source.Name),
			"Point Lockkeeper at the primary server for the migration."))
	}
	if tgt != nil && tgt.InRecovery {
		out = append(out, finding("target.recovery", areaTargetState, preflight.Blocker,
			fmt.Sprintf("the target %q is a standby (in recovery) and cannot accept writes", in.Target.Name),
			"Use the primary server as the migration target."))
	}
	return out
}
