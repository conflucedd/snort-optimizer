(function () {
  "use strict";

  const routes = [
    { key: "overview", label: "概览", icon: "◫" },
    { key: "analysis", label: "分析", icon: "◌" },
    { key: "rules", label: "规则", icon: "☰" },
    { key: "connections", label: "连接", icon: "⇄" },
    { key: "logs", label: "日志", icon: "⚑" },
  ];

  const state = {
    route: getRoute(),
    overview: null,
    statsHistory: [],
    recentAlerts: [],
    alertsOnline: false,
    statsOnline: false,
  };

  const app = document.getElementById("app");
  const pageCache = {};
  let contentEl = null;
  let navEl = null;

  bootstrap();

  function bootstrap() {
    app.innerHTML = `
      <div class="app-shell">
        <aside class="sidebar">
          <div class="brand">
            <div class="brand-mark">S3</div>
            <div class="brand-title">Snort</div>
            <div class="brand-subtitle">仿照 Yacd-meta 管理面板风格的 Snort 可视化控制台</div>
          </div>
          <nav class="nav-list" id="nav"></nav>
          <div class="sidebar-foot">
            HTTP + WebSocket 混合数据流
            <br />
            固定亮色主题，无登录、无代理相关页面
          </div>
        </aside>
        <main class="main" id="content"></main>
      </div>
    `;

    navEl = document.getElementById("nav");
    contentEl = document.getElementById("content");
    renderNav();
    showPage(state.route);
    window.addEventListener("hashchange", onRouteChange);

    connectStatsSocket();
    connectAlertsSocket();
    refreshOverview();
  }

  function onRouteChange() {
    state.route = getRoute();
    renderNav();
    showPage(state.route);
  }

  function renderNav() {
    navEl.innerHTML = routes
      .map(
        (route) => `
          <a class="nav-link ${route.key === state.route ? "active" : ""}" href="#/${route.key}">
            <span class="nav-icon">${route.icon}</span>
            <span>${route.label}</span>
          </a>
        `,
      )
      .join("");
  }

  function showPage(routeKey) {
    const route = routes.find((item) => item.key === routeKey) || routes[0];
    let page = pageCache[route.key];
    if (!page) {
      page = createPage(route.key);
      pageCache[route.key] = page;
    }
    Object.keys(pageCache).forEach((key) => {
      if (pageCache[key].hide) {
        pageCache[key].hide();
      }
    });
    contentEl.replaceChildren(page.el);
    if (page.show) {
      page.show();
    }
  }

  function createPage(key) {
    switch (key) {
      case "overview":
        return createOverviewPage();
      case "analysis":
        return createAnalysisPage();
      case "rules":
        return createRulesPage();
      case "connections":
        return createConnectionsPage();
      case "logs":
        return createLogsPage();
      default:
        return createOverviewPage();
    }
  }

  function createOverviewPage() {
    const el = document.createElement("section");
    el.className = "page";
    const refresh = async () => {
      try {
        state.overview = await apiGet("/api/overview");
      } catch (error) {
        state.overview = { errors: { overview: String(error) } };
      }
      render();
    };

    const render = () => {
      const overview = state.overview || {};
      const stats = overview.stats || {};
      const service = overview.service || {};
      const summary = overview.alert_summary || {};
      el.innerHTML = `
        <div class="page-head">
          <div>
            <h1 class="page-title">概览</h1>
            <div class="page-subtitle">Snort 进程状态、资源占用、规则规模与最近告警。</div>
          </div>
          <div class="live-pill ${state.statsOnline ? "" : "offline"}">${state.statsOnline ? "统计流在线" : "统计流离线"}</div>
        </div>

        <div class="card-grid">
          ${metricCard("Snort PID", stats.pid || service.snort_pid || "-", "当前运行进程")}
          ${metricCard("CPU 总时间", formatSeconds(stats.cpu_seconds), "来自后端实时 WS")}
          ${metricCard("内存 RSS", formatBytes(stats.memory_rss_bytes), "当前驻留内存")}
          ${metricCard("当前连接数", formatNumber(overview.connection_count), "来自 /proc/net")}
          ${metricCard("规则总数", formatNumber(overview.rule_count), "规则页支持搜索与虚拟滚动")}
          ${metricCard("总告警数", formatNumber(summary.total), "历史库累计")}
          ${metricCard("近 1 小时告警", formatNumber(summary.last_hour), "实时流会继续推送")}
          ${metricCard("近 24 小时告警", formatNumber(summary.last_24_hours), "唯一 SID: " + formatNumber(summary.unique_sids))}
        </div>

        <div class="split-grid">
          <section class="card">
            <h2 class="section-title">资源曲线</h2>
            ${renderSparkline(state.statsHistory, "cpu_seconds")}
            <div class="card-meta">展示最近 ${state.statsHistory.length} 个统计点，纵轴为 CPU 总时间。</div>
          </section>

          <section class="card">
            <h2 class="section-title">服务信息</h2>
            <div class="detail-grid">
              ${detailItem("监听地址", service.http_addr || "-")}
              ${detailItem("接口", service.interface || "-")}
              ${detailItem("PCAP", service.pcap || "-")}
              ${detailItem("配置文件", service.config_file || "-")}
              ${detailItem("规则数据库", service.rules_db || "-")}
              ${detailItem("告警数据库", service.alert_db || "-")}
            </div>
          </section>
        </div>

        <section class="card">
          <div class="page-head">
            <div>
              <h2 class="section-title">最近告警</h2>
              <div class="page-subtitle">优先展示最新的实时告警；如果还没收到实时数据，则显示最近的历史记录。</div>
            </div>
            <button class="control" id="overview-refresh">刷新概览</button>
          </div>
          <div class="stack">
            ${renderRecentAlerts()}
          </div>
        </section>
      `;
      el.querySelector("#overview-refresh").addEventListener("click", refresh);
    };

    refresh();
    return {
      el,
      show() {
        render();
      },
      refresh,
      onStats(stats) {
        render();
      },
      onAlert(alert) {
        render();
      },
    };
  }

  function createAnalysisPage() {
    const el = document.createElement("section");
    el.className = "page";
    el.innerHTML = `
      <div class="page-head">
        <div>
          <h1 class="page-title">分析</h1>
          <div class="page-subtitle">预留页面，后续可接入告警聚类、攻击画像、协议分布等分析模块。</div>
        </div>
      </div>
      <div class="placeholder">
        <div>
          <div style="font-size: 22px; font-weight: 700; color: var(--text); margin-bottom: 12px;">页面暂未实现</div>
          <div>当前仅保留入口和风格结构，避免把代理面板残留内容带进来。</div>
        </div>
      </div>
    `;
    return { el };
  }

  function createRulesPage() {
    const el = document.createElement("section");
    el.className = "page";
    const table = createVirtualTable({
      columns: "110px 140px minmax(560px, 1fr)",
      rowHeight: 58,
      renderRow: (row) => `
        <div class="cell-strong mono">${escapeHtml(String(row.sid))}</div>
        <div><span class="badge ${row.enabled ? "good" : "warn"}">${row.enabled ? "启用" : "停用"}</span></div>
        <div class="mono">${escapeHtml(row.raw_text)}</div>
      `,
      emptyText: "没有匹配到规则。",
    });
    let query = { search: "", offset: 0, total: 0, loading: false, exhausted: false };
    let items = [];

    async function load(reset) {
      if (query.loading || query.exhausted) {
        return;
      }
      query.loading = true;
      renderMeta();
      try {
        const result = await apiGet("/api/rules", {
          limit: 300,
          offset: reset ? 0 : items.length,
          search: query.search,
        });
        query.total = result.total || 0;
        items = reset ? result.items || [] : items.concat(result.items || []);
        query.exhausted = items.length >= query.total;
        table.setItems(items);
      } finally {
        query.loading = false;
        renderMeta();
      }
    }

    function renderMeta() {
      const meta = el.querySelector("[data-meta]");
      if (meta) {
        meta.textContent = `${formatNumber(items.length)} / ${formatNumber(query.total)} 条规则${query.loading ? " · 加载中" : ""}`;
      }
    }

    el.innerHTML = `
      <div class="page-head">
        <div>
          <h1 class="page-title">规则</h1>
          <div class="page-subtitle">分页读取 rules.db，只保留 Snort 规则信息。</div>
        </div>
      </div>
      <div class="controls">
        <label class="control">
          <span class="muted">搜索</span>
          <input type="search" placeholder="SID 或规则文本" />
        </label>
        <div class="toolbar-meta" data-meta></div>
      </div>
    `;
    el.appendChild(
      table.mount({
        headers: ["SID", "状态", "规则内容"],
      }),
    );

    const input = el.querySelector("input");
    input.addEventListener(
      "input",
      debounce(() => {
        query.search = input.value.trim();
        query.exhausted = false;
        items = [];
        table.setItems([]);
        load(true);
      }, 250),
    );

    table.onReachEnd(() => load(false));
    load(true);
    return { el, show: renderMeta };
  }

  function createConnectionsPage() {
    const el = document.createElement("section");
    el.className = "page";
    const table = createVirtualTable({
      columns: "88px 120px minmax(240px, 1fr) minmax(240px, 1fr) 96px 96px 82px",
      rowHeight: 58,
      renderRow: (row) => `
        <div class="cell-strong mono">${escapeHtml(row.protocol)}</div>
        <div><span class="badge ${row.state === "ESTABLISHED" ? "good" : row.state === "LISTEN" ? "warn" : "bad"}">${escapeHtml(row.state)}</span></div>
        <div class="mono">${escapeHtml(row.local_addr)}:${escapeHtml(String(row.local_port))}</div>
        <div class="mono">${escapeHtml(row.remote_addr)}:${escapeHtml(String(row.remote_port))}</div>
        <div class="mono">${formatBytes(row.tx_queue)}</div>
        <div class="mono">${formatBytes(row.rx_queue)}</div>
        <div class="mono">${escapeHtml(String(row.uid))}</div>
      `,
      emptyText: "当前没有匹配到连接。",
    });

    let refreshTimer = null;
    let query = { search: "", protocol: "", state: "", total: 0, loading: false, exhausted: false };
    let items = [];

    async function load(reset) {
      if (query.loading || query.exhausted) {
        return;
      }
      query.loading = true;
      renderMeta();
      try {
        const result = await apiGet("/api/connections", {
          limit: 300,
          offset: reset ? 0 : items.length,
          search: query.search,
          protocol: query.protocol,
          state: query.state,
        });
        query.total = result.total || 0;
        items = reset ? result.items || [] : items.concat(result.items || []);
        query.exhausted = items.length >= query.total;
        table.setItems(items);
      } finally {
        query.loading = false;
        renderMeta();
      }
    }

    function renderMeta() {
      const meta = el.querySelector("[data-meta]");
      if (meta) {
        meta.textContent = `${formatNumber(items.length)} / ${formatNumber(query.total)} 条连接${query.loading ? " · 刷新中" : ""}`;
      }
    }

    function resetAndLoad() {
      query.exhausted = false;
      items = [];
      table.setItems([]);
      load(true);
    }

    el.innerHTML = `
      <div class="page-head">
        <div>
          <h1 class="page-title">连接</h1>
          <div class="page-subtitle">读取当前服务器连接快照，支持大数据量滚动查看。</div>
        </div>
      </div>
      <div class="controls">
        <label class="control">
          <span class="muted">搜索</span>
          <input type="search" placeholder="地址 / 端口 / UID" data-search />
        </label>
        <label class="control">
          <span class="muted">协议</span>
          <select data-protocol>
            <option value="">全部</option>
            <option value="tcp">tcp</option>
            <option value="tcp6">tcp6</option>
            <option value="udp">udp</option>
            <option value="udp6">udp6</option>
          </select>
        </label>
        <label class="control">
          <span class="muted">状态</span>
          <select data-state>
            <option value="">全部</option>
            <option value="ESTABLISHED">ESTABLISHED</option>
            <option value="LISTEN">LISTEN</option>
            <option value="TIME_WAIT">TIME_WAIT</option>
            <option value="UNCONN">UNCONN</option>
          </select>
        </label>
        <button class="control" data-refresh>手动刷新</button>
        <div class="toolbar-meta" data-meta></div>
      </div>
    `;
    el.appendChild(
      table.mount({
        headers: ["协议", "状态", "本地地址", "远端地址", "发送队列", "接收队列", "UID"],
      }),
    );

    el.querySelector("[data-search]").addEventListener(
      "input",
      debounce((event) => {
        query.search = event.target.value.trim();
        resetAndLoad();
      }, 250),
    );
    el.querySelector("[data-protocol]").addEventListener("change", (event) => {
      query.protocol = event.target.value;
      resetAndLoad();
    });
    el.querySelector("[data-state]").addEventListener("change", (event) => {
      query.state = event.target.value;
      resetAndLoad();
    });
    el.querySelector("[data-refresh]").addEventListener("click", resetAndLoad);
    table.onReachEnd(() => load(false));

    return {
      el,
      show() {
        resetAndLoad();
        clearInterval(refreshTimer);
        refreshTimer = setInterval(resetAndLoad, 8000);
      },
      hide() {
        clearInterval(refreshTimer);
      },
    };
  }

  function createLogsPage() {
    const el = document.createElement("section");
    el.className = "page";
    const table = createVirtualTable({
      columns: "170px 100px minmax(240px, 1fr) minmax(220px, 1fr) minmax(220px, 1fr) 90px",
      rowHeight: 66,
      renderRow: (row) => `
        <div class="mono">${escapeHtml(formatTime(row.snort_timestamp || row.ingested_at))}</div>
        <div class="mono">${escapeHtml(String(row.sid || "-"))}</div>
        <div>${escapeHtml(row.rule || "-")}</div>
        <div class="mono">${escapeHtml(row.src_ap || "-")}</div>
        <div class="mono">${escapeHtml(row.dst_ap || "-")}</div>
        <div><span class="badge ${badgeClass(row.action)}">${escapeHtml(row.action || "-")}</span></div>
      `,
      emptyText: "没有匹配到报警日志。",
    });

    let loading = false;
    let filters = { sid: "", proto: "", rule: "", src: "", dst: "" };
    let items = [];
    let total = 0;
    let oldestId = 0;
    let exhausted = false;
    const knownIds = new Set();

    async function loadHistory(reset) {
      if (loading || exhausted) {
        return;
      }
      loading = true;
      renderMeta();
      try {
        const params = {
          limit: 200,
          sid: filters.sid,
          proto: filters.proto,
          rule: filters.rule,
          src: filters.src,
          dst: filters.dst,
        };
        if (!reset && oldestId > 0) {
          params.before_id = oldestId;
        }
        const result = await apiGet("/api/alerts", params);
        total = result.total || 0;
        const incoming = (result.items || []).filter((item) => {
          if (knownIds.has(item.id)) {
            return false;
          }
          knownIds.add(item.id);
          return true;
        });
        if (reset) {
          items = incoming;
        } else {
          items = items.concat(incoming);
        }
        oldestId = items.length ? items[items.length - 1].id : 0;
        exhausted = !incoming.length || items.length >= total;
        table.setItems(items);
      } finally {
        loading = false;
        renderMeta();
      }
    }

    function resetAndLoad() {
      loading = false;
      items = [];
      total = 0;
      oldestId = 0;
      exhausted = false;
      knownIds.clear();
      table.setItems([]);
      loadHistory(true);
    }

    function renderMeta() {
      const meta = el.querySelector("[data-meta]");
      if (meta) {
        meta.textContent = `${formatNumber(items.length)} / ${formatNumber(total)} 条日志${loading ? " · 加载中" : ""}`;
      }
      const live = el.querySelector("[data-live]");
      if (live) {
        live.className = `live-pill ${state.alertsOnline ? "" : "offline"}`;
        live.textContent = state.alertsOnline ? "告警流在线" : "告警流离线";
      }
    }

    function matchesFilters(alert) {
      if (filters.sid && String(alert.sid) !== filters.sid) {
        return false;
      }
      if (filters.proto && String(alert.proto || "").toLowerCase() !== filters.proto.toLowerCase()) {
        return false;
      }
      if (filters.rule && !String(alert.rule || "").toLowerCase().includes(filters.rule.toLowerCase())) {
        return false;
      }
      if (filters.src && !String(alert.src_ap || "").toLowerCase().includes(filters.src.toLowerCase())) {
        return false;
      }
      if (filters.dst && !String(alert.dst_ap || "").toLowerCase().includes(filters.dst.toLowerCase())) {
        return false;
      }
      return true;
    }

    el.innerHTML = `
      <div class="page-head">
        <div>
          <h1 class="page-title">日志</h1>
          <div class="page-subtitle">历史查询走 HTTP，新增告警通过 WS 直接插入顶部。</div>
        </div>
        <div class="live-pill" data-live></div>
      </div>
      <div class="controls">
        <label class="control"><span class="muted">SID</span><input type="search" data-sid placeholder="例如 1000001" /></label>
        <label class="control"><span class="muted">协议</span><input type="search" data-proto placeholder="TCP / UDP" /></label>
        <label class="control"><span class="muted">规则</span><input type="search" data-rule placeholder="规则文本" /></label>
        <label class="control"><span class="muted">源地址</span><input type="search" data-src placeholder="源 IP:Port" /></label>
        <label class="control"><span class="muted">目的地址</span><input type="search" data-dst placeholder="目的 IP:Port" /></label>
        <button class="control" data-refresh>刷新</button>
        <div class="toolbar-meta" data-meta></div>
      </div>
    `;
    el.appendChild(
      table.mount({
        headers: ["时间", "SID", "规则", "源地址", "目的地址", "动作"],
      }),
    );

    ["sid", "proto", "rule", "src", "dst"].forEach((key) => {
      el.querySelector(`[data-${key}]`).addEventListener(
        "input",
        debounce((event) => {
          filters[key] = event.target.value.trim();
          resetAndLoad();
        }, 250),
      );
    });
    el.querySelector("[data-refresh]").addEventListener("click", resetAndLoad);
    table.onReachEnd(() => loadHistory(false));

    return {
      el,
      show() {
        renderMeta();
        if (!items.length) {
          resetAndLoad();
        }
      },
      onAlert(alert) {
        if (!matchesFilters(alert) || knownIds.has(alert.id)) {
          return;
        }
        knownIds.add(alert.id);
        items.unshift(alert);
        total += 1;
        table.setItems(items);
        renderMeta();
      },
      onSocketState() {
        renderMeta();
      },
    };
  }

  function createVirtualTable(options) {
    const rowHeight = options.rowHeight || 56;
    const host = document.createElement("section");
    host.className = "table-shell";
    host.style.setProperty("--row-height", `${rowHeight}px`);
    let items = [];
    let reachEndHandler = null;

    host.innerHTML = `
      <div class="table-head"></div>
      <div class="table-viewport">
        <div class="table-spacer"></div>
      </div>
    `;

    const head = host.querySelector(".table-head");
    const viewport = host.querySelector(".table-viewport");
    const spacer = host.querySelector(".table-spacer");

    function renderRows() {
      const widthTemplate = options.columns;
      head.style.gridTemplateColumns = widthTemplate;
      const viewportHeight = viewport.clientHeight || 400;
      const overscan = 6;
      const start = Math.max(0, Math.floor(viewport.scrollTop / rowHeight) - overscan);
      const end = Math.min(items.length, Math.ceil((viewport.scrollTop + viewportHeight) / rowHeight) + overscan);
      spacer.style.height = `${items.length * rowHeight}px`;
      spacer.innerHTML = "";

      if (!items.length) {
        spacer.innerHTML = `<div class="empty-state">${escapeHtml(options.emptyText || "暂无数据")}</div>`;
        spacer.style.height = "auto";
        return;
      }

      const fragment = document.createDocumentFragment();
      for (let index = start; index < end; index += 1) {
        const row = document.createElement("div");
        row.className = "table-row";
        row.style.gridTemplateColumns = widthTemplate;
        row.style.top = `${index * rowHeight}px`;
        row.innerHTML = options.renderRow(items[index], index);
        fragment.appendChild(row);
      }
      spacer.appendChild(fragment);
    }

    viewport.addEventListener("scroll", () => {
      renderRows();
      if (reachEndHandler && viewport.scrollTop + viewport.clientHeight >= spacer.scrollHeight - rowHeight * 8) {
        reachEndHandler();
      }
    });
    window.addEventListener("resize", renderRows);

    return {
      mount(config) {
        head.style.gridTemplateColumns = options.columns;
        head.innerHTML = (config.headers || []).map((label) => `<div>${escapeHtml(label)}</div>`).join("");
        return host;
      },
      setItems(nextItems) {
        items = Array.isArray(nextItems) ? nextItems.slice() : [];
        renderRows();
      },
      onReachEnd(handler) {
        reachEndHandler = handler;
      },
    };
  }

  function connectStatsSocket() {
    const url = toWebSocketURL("/ws/stats");
    const socket = new WebSocket(url);
    socket.addEventListener("open", () => {
      state.statsOnline = true;
      notifyPages("onSocketState");
    });
    socket.addEventListener("message", (event) => {
      const payload = safeJSON(event.data);
      if (!payload || payload.error) {
        return;
      }
      state.statsOnline = true;
      state.statsHistory.push(payload);
      if (state.statsHistory.length > 60) {
        state.statsHistory = state.statsHistory.slice(-60);
      }
      if (!state.overview) {
        state.overview = {};
      }
      state.overview.stats = payload;
      notifyPages("onStats", payload);
    });
    socket.addEventListener("close", () => {
      state.statsOnline = false;
      notifyPages("onSocketState");
      setTimeout(connectStatsSocket, 1500);
    });
    socket.addEventListener("error", () => socket.close());
  }

  function connectAlertsSocket() {
    const url = toWebSocketURL("/ws/alerts");
    const socket = new WebSocket(url);
    socket.addEventListener("open", () => {
      state.alertsOnline = true;
      notifyPages("onSocketState");
    });
    socket.addEventListener("message", (event) => {
      const payload = safeJSON(event.data);
      if (!payload || payload.error) {
        return;
      }
      state.alertsOnline = true;
      state.recentAlerts.unshift(payload);
      state.recentAlerts = state.recentAlerts.slice(0, 12);
      notifyPages("onAlert", payload);
    });
    socket.addEventListener("close", () => {
      state.alertsOnline = false;
      notifyPages("onSocketState");
      setTimeout(connectAlertsSocket, 1500);
    });
    socket.addEventListener("error", () => socket.close());
  }

  async function refreshOverview() {
    try {
      const [overview, recent] = await Promise.all([
        apiGet("/api/overview"),
        apiGet("/api/alerts", { limit: 12 }),
      ]);
      state.overview = overview;
      if (!state.recentAlerts.length) {
        state.recentAlerts = recent.items || [];
      }
      notifyPages("refresh");
    } catch (error) {
      console.error(error);
    }
  }

  async function apiGet(path, params) {
    const url = new URL(path, window.location.origin);
    Object.entries(params || {}).forEach(([key, value]) => {
      if (value !== "" && value !== undefined && value !== null) {
        url.searchParams.set(key, value);
      }
    });
    const response = await fetch(url.toString(), { headers: { Accept: "application/json" } });
    if (!response.ok) {
      throw new Error(`${response.status} ${response.statusText}`);
    }
    return response.json();
  }

  function notifyPages(method, payload) {
    Object.values(pageCache).forEach((page) => {
      if (page && typeof page[method] === "function") {
        page[method](payload);
      }
    });
  }

  function metricCard(label, value, meta) {
    return `
      <section class="card">
        <div class="card-label">${escapeHtml(label)}</div>
        <div class="card-value">${escapeHtml(String(value == null ? "-" : value))}</div>
        <div class="card-meta">${escapeHtml(meta || "")}</div>
      </section>
    `;
  }

  function detailItem(label, value) {
    return `
      <div class="detail-item">
        <div class="detail-key">${escapeHtml(label)}</div>
        <div class="detail-value">${escapeHtml(String(value == null ? "-" : value))}</div>
      </div>
    `;
  }

  function renderRecentAlerts() {
    if (!state.recentAlerts.length) {
      return `<div class="empty-state">暂无告警数据。</div>`;
    }
    return state.recentAlerts
      .slice(0, 6)
      .map(
        (item) => `
          <div class="alert-item">
            <div class="alert-topline">
              <div class="cell-strong">${escapeHtml(item.rule || "-")}</div>
              <span class="badge ${badgeClass(item.action)}">${escapeHtml(item.action || "-")}</span>
            </div>
            <div class="muted mono">${escapeHtml(formatTime(item.snort_timestamp || item.ingested_at))}</div>
            <div class="card-meta mono">${escapeHtml(item.src_ap || "-")} -> ${escapeHtml(item.dst_ap || "-")}</div>
          </div>
        `,
      )
      .join("");
  }

  function renderSparkline(points, key) {
    if (!points.length) {
      return `<div class="placeholder" style="min-height: 180px;">等待统计数据…</div>`;
    }
    const values = points.map((point) => Number(point[key] || 0));
    const min = Math.min.apply(null, values);
    const max = Math.max.apply(null, values);
    const width = 700;
    const height = 180;
    const step = values.length > 1 ? width / (values.length - 1) : width;
    const coords = values.map((value, index) => {
      const y = max === min ? height / 2 : height - ((value - min) / (max - min)) * (height - 24) - 12;
      return `${index * step},${y}`;
    });
    const line = coords.join(" ");
    const fill = `0,${height} ${coords.join(" ")} ${width},${height}`;
    return `
      <svg class="sparkline" viewBox="0 0 ${width} ${height}" preserveAspectRatio="none">
        <path class="fill" d="M ${fill}" />
        <polyline class="line" points="${line}" fill="none" stroke-linecap="round" stroke-linejoin="round"></polyline>
      </svg>
    `;
  }

  function getRoute() {
    const hash = window.location.hash.replace(/^#\/?/, "");
    return routes.some((route) => route.key === hash) ? hash : "overview";
  }

  function toWebSocketURL(path) {
    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    return `${protocol}//${window.location.host}${path}`;
  }

  function formatBytes(value) {
    const num = Number(value || 0);
    if (!Number.isFinite(num)) {
      return "-";
    }
    if (num < 1024) {
      return `${num} B`;
    }
    const units = ["KB", "MB", "GB", "TB"];
    let current = num;
    let unit = "B";
    for (let index = 0; index < units.length; index += 1) {
      current /= 1024;
      unit = units[index];
      if (current < 1024) {
        break;
      }
    }
    return `${current.toFixed(current >= 100 ? 0 : current >= 10 ? 1 : 2)} ${unit}`;
  }

  function formatSeconds(value) {
    const num = Number(value || 0);
    if (!Number.isFinite(num)) {
      return "-";
    }
    return `${num.toFixed(2)} s`;
  }

  function formatNumber(value) {
    const num = Number(value || 0);
    if (!Number.isFinite(num)) {
      return "-";
    }
    return num.toLocaleString("zh-CN");
  }

  function formatTime(value) {
    if (!value) {
      return "-";
    }
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) {
      return String(value);
    }
    return new Intl.DateTimeFormat("zh-CN", {
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: false,
    }).format(date);
  }

  function escapeHtml(value) {
    return String(value)
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#39;");
  }

  function badgeClass(action) {
    const value = String(action || "").toLowerCase();
    if (value.includes("allow")) {
      return "good";
    }
    if (value.includes("alert")) {
      return "bad";
    }
    return "warn";
  }

  function safeJSON(text) {
    try {
      return JSON.parse(text);
    } catch (_) {
      return null;
    }
  }

  function debounce(fn, wait) {
    let timer = 0;
    return function debounced(...args) {
      window.clearTimeout(timer);
      timer = window.setTimeout(() => fn.apply(this, args), wait);
    };
  }
})();
