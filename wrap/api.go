package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"
)

type APIServer struct {
	cfg        RuntimeConfig
	alertStore *AlertStore
	broker     *AlertBroker
	snort      *SnortRunner
	logger     *log.Logger
	server     *http.Server
}

func NewAPIServer(cfg RuntimeConfig, alertStore *AlertStore, broker *AlertBroker, snort *SnortRunner, logger *log.Logger) *APIServer {
	api := &APIServer{
		cfg:        cfg,
		alertStore: alertStore,
		broker:     broker,
		snort:      snort,
		logger:     logger,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/health", api.handleHealth)
	mux.HandleFunc("/api/overview", api.handleOverview)
	mux.HandleFunc("/api/alerts", api.handleAlertHistory)
	mux.HandleFunc("/api/rules", api.handleRules)
	mux.HandleFunc("/api/connections", api.handleConnections)
	mux.HandleFunc("/ws/stats", api.handleStatsWS)
	mux.HandleFunc("/ws/alerts", api.handleAlertsWS)

	if stat, err := os.Stat(cfg.Paths.SiteDir); err == nil && stat.IsDir() {
		mux.Handle("/", http.FileServer(http.Dir(cfg.Paths.SiteDir)))
	}

	api.server = &http.Server{
		Addr:    cfg.HTTPAddr,
		Handler: mux,
	}
	return api
}

func (a *APIServer) ListenAndServe(ctx context.Context) error {
	errCh := make(chan error, 1)
	go func() {
		a.logger.Printf("http server listening on %s", a.cfg.HTTPAddr)
		errCh <- a.server.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = a.server.Shutdown(shutdownCtx)
		return ctx.Err()
	case err := <-errCh:
		return err
	}
}

func (a *APIServer) handleHealth(w http.ResponseWriter, _ *http.Request) {
	stats, err := a.snort.Stats()
	payload := map[string]any{
		"ok":          err == nil,
		"http_addr":   a.cfg.HTTPAddr,
		"snort_pid":   a.snort.PID(),
		"alert_db":    a.cfg.Paths.AlertDBPath,
		"rules_db":    a.cfg.Paths.RulesDBPath,
		"all_rules":   a.cfg.Paths.AllRulesPath,
		"stats_error": "",
		"stats":       stats,
	}
	if err != nil {
		payload["stats_error"] = err.Error()
	}
	writeJSON(w, http.StatusOK, payload)
}

func (a *APIServer) handleAlertHistory(w http.ResponseWriter, r *http.Request) {
	query := AlertQuery{
		Limit:    clamp(ParseIntDefault(r.URL.Query().Get("limit"), 100), 1, 500),
		Offset:   max(ParseIntDefault(r.URL.Query().Get("offset"), 0), 0),
		BeforeID: int64(max(ParseIntDefault(r.URL.Query().Get("before_id"), 0), 0)),
		SID:      max(ParseIntDefault(r.URL.Query().Get("sid"), 0), 0),
		Action:   r.URL.Query().Get("action"),
		Proto:    r.URL.Query().Get("proto"),
		Rule:     r.URL.Query().Get("rule"),
		Src:      r.URL.Query().Get("src"),
		Dst:      r.URL.Query().Get("dst"),
	}

	result, err := a.alertStore.Query(query)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (a *APIServer) handleOverview(w http.ResponseWriter, _ *http.Request) {
	stats, statsErr := a.snort.Stats()
	alertSummary, alertsErr := a.alertStore.Summary()
	ruleCount, rulesErr := CountRules(a.cfg.Paths.RulesDBPath)
	connectionCount, connErr := CountConnections()

	payload := map[string]any{
		"service": map[string]any{
			"http_addr":   a.cfg.HTTPAddr,
			"snort_pid":   a.snort.PID(),
			"config_file": a.cfg.Paths.ConfigFile,
			"rules_db":    a.cfg.Paths.RulesDBPath,
			"alert_db":    a.cfg.Paths.AlertDBPath,
			"site_dir":    a.cfg.Paths.SiteDir,
			"interface":   a.cfg.Interface,
			"pcap":        a.cfg.PCAPPath,
		},
		"stats":            stats,
		"alert_summary":    alertSummary,
		"rule_count":       ruleCount,
		"connection_count": connectionCount,
		"errors": map[string]string{
			"stats":       errString(statsErr),
			"alerts":      errString(alertsErr),
			"rules":       errString(rulesErr),
			"connections": errString(connErr),
		},
	}
	writeJSON(w, http.StatusOK, payload)
}

func (a *APIServer) handleRules(w http.ResponseWriter, r *http.Request) {
	query := RuleQuery{
		Limit:  clamp(ParseIntDefault(r.URL.Query().Get("limit"), 200), 1, 1000),
		Offset: max(ParseIntDefault(r.URL.Query().Get("offset"), 0), 0),
		Search: r.URL.Query().Get("search"),
	}
	result, err := QueryRules(a.cfg.Paths.RulesDBPath, query)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (a *APIServer) handleConnections(w http.ResponseWriter, r *http.Request) {
	query := ConnectionQuery{
		Limit:    clamp(ParseIntDefault(r.URL.Query().Get("limit"), 200), 1, 1000),
		Offset:   max(ParseIntDefault(r.URL.Query().Get("offset"), 0), 0),
		Protocol: r.URL.Query().Get("protocol"),
		State:    r.URL.Query().Get("state"),
		Search:   r.URL.Query().Get("search"),
	}
	result, err := QueryConnections(query)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (a *APIServer) handleStatsWS(w http.ResponseWriter, r *http.Request) {
	conn, err := UpgradeWebSocket(w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	defer conn.Close()

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		stats, err := a.snort.Stats()
		if err != nil {
			if writeWSError(conn, err) != nil {
				return
			}
		} else {
			if err := conn.WriteJSON(stats); err != nil {
				return
			}
		}

		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
		}
	}
}

func (a *APIServer) handleAlertsWS(w http.ResponseWriter, r *http.Request) {
	conn, err := UpgradeWebSocket(w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	defer conn.Close()

	ch := a.broker.Subscribe()
	defer a.broker.Unsubscribe(ch)

	for {
		select {
		case <-r.Context().Done():
			return
		case alert, ok := <-ch:
			if !ok {
				return
			}
			if err := conn.WriteJSON(alert); err != nil {
				return
			}
		}
	}
}

func writeWSError(conn *WebSocketConn, err error) error {
	return conn.WriteJSON(map[string]any{
		"error":     err.Error(),
		"timestamp": time.Now(),
	})
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func clamp(value, minValue, maxValue int) int {
	if value < minValue {
		return minValue
	}
	if value > maxValue {
		return maxValue
	}
	return value
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
