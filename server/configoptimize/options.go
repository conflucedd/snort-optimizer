package configoptimize

import "snort-optimizer/server/store"

type LuaPreset struct {
	ID          string `json:"id"`
	Category    string `json:"category"`
	Label       string `json:"label"`
	Value       string `json:"value"`
	Description string `json:"description"`
	Risk        string `json:"risk"`
}

func Presets() []LuaPreset {
	return []LuaPreset{
		{
			ID:          "search_hyperscan",
			Category:    "检测引擎",
			Label:       "Hyperscan 搜索引擎",
			Value:       `search_engine = { search_method = "hyperscan" }`,
			Description: "启用 Hyperscan 多模式匹配，通常能降低规则匹配耗时；需要 Snort 构建时支持 Hyperscan。",
			Risk:        "medium",
		},
		{
			ID:          "search_ac_bnfa",
			Category:    "检测引擎",
			Label:       "AC-BNFA 搜索引擎",
			Value:       `search_engine = { search_method = "ac_bnfa" }`,
			Description: "使用内存占用较低的 AC-BNFA，适合 Hyperscan 不可用或内存紧张的机器。",
			Risk:        "low",
		},
		{
			ID:          "appid_disable",
			Category:    "协议识别",
			Label:       "关闭 AppID",
			Value:       `appid = nil`,
			Description: "减少应用识别开销。依赖 AppID 的规则或统计会变少，应用前建议先跑总体性能测试。",
			Risk:        "high",
		},
		{
			ID:          "stream_tcp_prune",
			Category:    "会话跟踪",
			Label:       "限制 TCP 会话缓存",
			Value:       `stream_tcp = { session_timeout = 60 }`,
			Description: "缩短 TCP 会话保留时间，降低高连接数场景的内存压力。",
			Risk:        "medium",
		},
		{
			ID:          "wizard_disable",
			Category:    "协议识别",
			Label:       "关闭 Wizard 探测",
			Value:       `wizard = nil`,
			Description: "关闭部分协议自动探测，减少早期流量分类成本。",
			Risk:        "medium",
		},
		{
			ID:          "latency_guard",
			Category:    "延迟保护",
			Label:       "启用延迟保护",
			Value:       `latency = { packet = { max_time = 1500 }, rule = { max_time = 1500 } }`,
			Description: "对异常慢包和慢规则设置时间上限，保护生产流量延迟。",
			Risk:        "medium",
		},
		{
			ID:          "inspect_file_depth",
			Category:    "文件检测",
			Label:       "限制文件检测深度",
			Value:       `file_id = { file_rules = false }`,
			Description: "降低文件识别和文件规则开销，适合非文件安全场景。",
			Risk:        "high",
		},
	}
}

func DefaultLuaOverrides() []store.LuaOverride {
	presets := Presets()
	out := make([]store.LuaOverride, 0, len(presets))
	for _, preset := range presets {
		out = append(out, store.LuaOverride{
			ID:          preset.ID,
			Label:       preset.Label,
			Value:       preset.Value,
			Enabled:     false,
			Description: preset.Description,
			Category:    preset.Category,
		})
	}
	return out
}

func MergePresetMetadata(overrides []store.LuaOverride) []store.LuaOverride {
	meta := map[string]LuaPreset{}
	for _, preset := range Presets() {
		meta[preset.ID] = preset
	}
	seen := map[string]bool{}
	out := make([]store.LuaOverride, 0, len(overrides)+len(meta))
	for _, override := range overrides {
		if preset, ok := meta[override.ID]; ok {
			override.Value = preset.Value
			if override.Label == "" {
				override.Label = preset.Label
			}
			if override.Description == "" {
				override.Description = preset.Description
			}
			if override.Category == "" {
				override.Category = preset.Category
			}
		}
		out = append(out, override)
		seen[override.ID] = true
	}
	for _, preset := range Presets() {
		if seen[preset.ID] {
			continue
		}
		out = append(out, store.LuaOverride{
			ID:          preset.ID,
			Label:       preset.Label,
			Value:       preset.Value,
			Description: preset.Description,
			Category:    preset.Category,
		})
	}
	return out
}

func EnabledLuaValues(overrides []store.LuaOverride) []string {
	out := make([]string, 0, len(overrides))
	for _, override := range overrides {
		if override.Enabled && override.Value != "" {
			out = append(out, override.Value)
		}
	}
	return out
}
