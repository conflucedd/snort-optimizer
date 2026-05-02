package safe

import (
	"context"
	"database/sql"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"snort-optimizer/analyser/types"
)

type systemdServiceRuleGroup struct {
	name        string
	units       []string
	sourceFiles []string
	services    []string
}

var commonSystemdServiceRuleGroups = []systemdServiceRuleGroup{
	{
		name:        "http",
		units:       []string{"nginx.service", "apache2.service", "httpd.service", "caddy.service", "lighttpd.service"},
		sourceFiles: []string{"snort3-server-apache.rules", "snort3-server-iis.rules", "snort3-server-webapp.rules"},
		services:    []string{"http", "http2"},
	},
	{
		name:     "ssh",
		units:    []string{"ssh.service", "sshd.service"},
		services: []string{"ssh"},
	},
	{
		name:        "ftp",
		units:       []string{"vsftpd.service", "proftpd.service", "pure-ftpd.service", "ftp.service"},
		sourceFiles: []string{"snort3-protocol-ftp.rules"},
		services:    []string{"ftp", "ftp-data"},
	},
	{
		name:        "mail",
		units:       []string{"postfix.service", "exim.service", "exim4.service", "sendmail.service", "dovecot.service"},
		sourceFiles: []string{"snort3-server-mail.rules", "snort3-protocol-imap.rules", "snort3-protocol-pop.rules"},
		services:    []string{"smtp", "imap", "pop3"},
	},
	{
		name:        "dns",
		units:       []string{"named.service", "bind9.service", "dnsmasq.service", "unbound.service", "pdns.service"},
		sourceFiles: []string{"snort3-protocol-dns.rules"},
		services:    []string{"dns"},
	},
	{
		name:        "mysql",
		units:       []string{"mysql.service", "mysqld.service", "mariadb.service"},
		sourceFiles: []string{"snort3-server-mysql.rules"},
		services:    []string{"mysql"},
	},
	{
		name:        "mssql",
		units:       []string{"mssql-server.service"},
		sourceFiles: []string{"snort3-server-mssql.rules"},
		services:    []string{"mssql"},
	},
	{
		name:        "oracle",
		units:       []string{"oracle.service", "oracle-xe.service"},
		sourceFiles: []string{"snort3-server-oracle.rules"},
		services:    []string{"oracle"},
	},
	{
		name:        "samba",
		units:       []string{"smb.service", "smbd.service", "nmb.service", "nmbd.service", "samba.service", "winbind.service"},
		sourceFiles: []string{"snort3-server-samba.rules", "snort3-netbios.rules"},
		services:    []string{"netbios-ssn", "smb"},
	},
	{
		name:        "snmp",
		units:       []string{"snmpd.service"},
		sourceFiles: []string{"snort3-protocol-snmp.rules"},
		services:    []string{"snmp"},
	},
	{
		name:        "telnet",
		units:       []string{"telnet.service", "telnet.socket", "telnetd.service"},
		sourceFiles: []string{"snort3-protocol-telnet.rules"},
		services:    []string{"telnet"},
	},
	{
		name:        "rpc",
		units:       []string{"rpcbind.service", "nfs-server.service"},
		sourceFiles: []string{"snort3-protocol-rpc.rules"},
		services:    []string{"rpc", "sunrpc"},
	},
}

func InactiveSystemdServices() types.RegisteredFunction {
	return types.RegisteredFunction{
		Name: "safe_inactive_systemd_services",
		Type: types.SAFE,
		Fn:   InactiveSystemdServicesFunc,
	}
}

func InactiveSystemdServicesFunc(ctx context.Context, input types.FunctionInput) ([]types.TrimDecision, error) {
	active, ok, err := activeSystemdUnits(ctx)
	if err != nil || !ok {
		return nil, err
	}
	disabledSources := map[string]string{}
	disabledServices := map[string]string{}
	for _, group := range commonSystemdServiceRuleGroups {
		if groupHasActiveUnit(group, active) {
			continue
		}
		for _, source := range group.sourceFiles {
			disabledSources[source] = group.name
		}
		for _, service := range group.services {
			disabledServices[service] = group.name
		}
	}
	if len(disabledSources) == 0 && len(disabledServices) == 0 {
		return nil, nil
	}

	conn, err := sql.Open("sqlite", input.ExpDBPath)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	rows, err := conn.QueryContext(ctx, `SELECT gid, sid, rev, COALESCE(source_file, ''), COALESCE(msg, ''), COALESCE(raw_text, '')
FROM rules
WHERE run_id = ? AND enabled = 1
ORDER BY gid, sid;`, input.SourceRunID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	seen := map[string]struct{}{}
	var out []types.TrimDecision
	for rows.Next() {
		var d types.TrimDecision
		var raw string
		if err := rows.Scan(&d.GID, &d.SID, &d.Rev, &d.SourceFile, &d.Msg, &raw); err != nil {
			return nil, err
		}
		group, matched := disabledSources[sourceFileBase(d.SourceFile)]
		matchedBy := "source_file"
		if !matched {
			for _, service := range ruleServices(raw) {
				if serviceGroup, ok := disabledServices[service]; ok {
					group = serviceGroup
					matched = true
					matchedBy = "service"
					break
				}
			}
		}
		if !matched {
			continue
		}
		key := fmt.Sprintf("%d:%d", d.GID, d.SID)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		d.Reason = fmt.Sprintf("%s rule belongs to inactive systemd service group %q", matchedBy, group)
		out = append(out, d)
	}
	return out, rows.Err()
}

func activeSystemdUnits(ctx context.Context) (map[string]struct{}, bool, error) {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return nil, false, nil
	}
	runCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(runCtx, "systemctl", "list-units", "--type=service", "--type=socket", "--state=active", "--no-legend", "--no-pager", "--plain")
	output, err := cmd.Output()
	if runCtx.Err() != nil {
		return nil, false, runCtx.Err()
	}
	if err != nil {
		return nil, false, nil
	}
	active := map[string]struct{}{}
	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		active[strings.ToLower(fields[0])] = struct{}{}
	}
	if len(active) == 0 {
		return nil, false, nil
	}
	return active, true, nil
}

func groupHasActiveUnit(group systemdServiceRuleGroup, active map[string]struct{}) bool {
	for _, unit := range group.units {
		if _, ok := active[strings.ToLower(unit)]; ok {
			return true
		}
	}
	return false
}

func ruleServices(raw string) []string {
	lower := strings.ToLower(raw)
	var out []string
	for offset := 0; offset < len(lower); {
		pos := strings.Index(lower[offset:], "service:")
		if pos < 0 {
			break
		}
		start := offset + pos + len("service:")
		end := strings.Index(lower[start:], ";")
		if end < 0 {
			break
		}
		value := lower[start : start+end]
		for _, service := range strings.FieldsFunc(value, func(r rune) bool {
			return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
		}) {
			service = strings.TrimSpace(service)
			if service != "" {
				out = append(out, service)
			}
		}
		offset = start + end + 1
	}
	return out
}
