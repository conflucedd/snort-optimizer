package types

const (
	ModeInterface = "interface"
	ModePCAP      = "pcap"
)

type Config struct {
	Mode            string
	SnortWorkingDir string
	SnortConfigPath string
	SnortDBPath     string
	RawRulePath     string
	Interface       string
	PcapFile        string
	LuaOverrides    []string
	RunID           int64
	NeedOutput      bool
	NeedAlert       bool
	NeedProfiler    bool
	NoClean         bool
}
