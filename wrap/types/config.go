package types

const (
	ModeInterface = "interface"
	ModePCAP      = "pcap"
)

type Config struct {
	Mode            string
	SnortWorkingDir string
	SnortConfigPath string
	Interface       string
	PcapFile        string
	LuaOverrides    []string
	NeedOutput      bool
	NeedAlert       bool
}
