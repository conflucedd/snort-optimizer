package safe

import (
	"context"
	"database/sql"
	"fmt"
	"path"
	"strings"

	"snort-optimizer/analyser/types"
)

var uncommonProtocolSourceFiles = map[string]string{
	"snort3-netbios.rules":         "netbios is normally a LAN/gateway exposure, not a generic server workload",
	"snort3-protocol-finger.rules": "finger is a legacy protocol that is usually disabled on servers",
	"snort3-protocol-nntp.rules":   "nntp is uncommon for generic server workloads",
	"snort3-protocol-rpc.rules":    "rpc rules are gateway-oriented unless the host exposes RPC/NFS",
	"snort3-protocol-scada.rules":  "scada/industrial protocols are not expected on generic servers",
	"snort3-protocol-snmp.rules":   "snmp is usually infrastructure/gateway traffic",
	"snort3-protocol-telnet.rules": "telnet is a legacy protocol that is usually disabled on servers",
	"snort3-protocol-tftp.rules":   "tftp is uncommon for generic server workloads",
	"snort3-protocol-voip.rules":   "voip signaling is uncommon for generic server workloads",
	"snort3-x11.rules":             "x11 is not expected on exposed server workloads",
}

func SourceFileProtocols() types.RegisteredFunction {
	return types.RegisteredFunction{
		Name: "safe_source_file_protocols",
		Type: types.SAFE,
		Fn:   SourceFileProtocolsFunc,
	}
}

func SourceFileProtocolsFunc(ctx context.Context, input types.FunctionInput) ([]types.TrimDecision, error) {
	conn, err := sql.Open("sqlite", input.ExpDBPath)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	rows, err := conn.QueryContext(ctx, `SELECT gid, sid, rev, COALESCE(source_file, ''), COALESCE(msg, '')
FROM rules
WHERE run_id = ? AND enabled = 1
ORDER BY gid, sid;`, input.SourceRunID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []types.TrimDecision
	for rows.Next() {
		var d types.TrimDecision
		if err := rows.Scan(&d.GID, &d.SID, &d.Rev, &d.SourceFile, &d.Msg); err != nil {
			return nil, err
		}
		base := sourceFileBase(d.SourceFile)
		reason, ok := uncommonProtocolSourceFiles[base]
		if !ok {
			continue
		}
		d.Reason = fmt.Sprintf("source_file %q is disabled by server profile: %s", d.SourceFile, reason)
		out = append(out, d)
	}
	return out, rows.Err()
}

func sourceFileBase(value string) string {
	value = strings.ToLower(strings.TrimSpace(strings.ReplaceAll(value, "\\", "/")))
	return path.Base(value)
}
