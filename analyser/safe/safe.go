package safe

import "snort-optimizer/analyser"

func SourceFileBrowser() analyser.RegisteredFunction {
	return analyser.RegisteredFunction{
		Name: "safe_source_file_browser",
		Type: analyser.SAFE,
		Fn:   analyser.SafeSourceFileBrowser,
	}
}
