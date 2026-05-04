import { Search } from "lucide-react";
import { useEffect, useState } from "react";
import { api, fmtNumber } from "../api";
import type { AlertList, Settings } from "../types";

type Props = {
  settings?: Settings;
};

export function Alerts({ settings }: Props) {
  const [data, setData] = useState<AlertList>();
  const [query, setQuery] = useState("");
  const [sid, setSid] = useState("");
  const [offset, setOffset] = useState(0);
  const [error, setError] = useState("");
  const limit = 100;

  async function load(nextOffset = offset) {
    const params = new URLSearchParams({
      run_id: String(settings?.active_run_id ?? 0),
      limit: String(limit),
      offset: String(nextOffset)
    });
    if (query) params.set("q", query);
    if (sid) params.set("sid", sid);
    try {
      setData(await api.alerts(params));
      setError("");
    } catch (err) {
      setError((err as Error).message);
    }
  }

  useEffect(() => {
    load(0);
  }, [settings?.active_run_id]);

  function page(delta: number) {
    const next = Math.max(0, offset + delta * limit);
    setOffset(next);
    load(next);
  }

  return (
    <div className="page">
      <header className="page-head">
        <div>
          <h1>警告</h1>
          <div className="muted">总量 {fmtNumber(data?.total ?? 0)}</div>
        </div>
        <div className="searchbar">
          <Search size={16} />
          <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="规则、源、目的" />
          <input className="sid-input" value={sid} onChange={(event) => setSid(event.target.value)} placeholder="SID" />
          <button onClick={() => load(0)}>查询</button>
        </div>
      </header>
      {error ? <div className="banner bad">{error}</div> : null}

      <section className="panel">
        <div className="panel-title">告警流</div>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Time</th>
                <th>Rule</th>
                <th>Proto</th>
                <th>Source</th>
                <th>Destination</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {(data?.items ?? []).map((item) => (
                <tr key={item.id}>
                  <td>{item.timestamp || item.created_at}</td>
                  <td>
                    <strong>{item.gid}:{item.sid}</strong>
                    <span>{item.rule}</span>
                  </td>
                  <td>{item.proto}</td>
                  <td>{item.src_ap}</td>
                  <td>{item.dst_ap}</td>
                  <td>{item.action}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="pager">
          <button disabled={offset === 0} onClick={() => page(-1)}>上一页</button>
          <span>
            {fmtNumber(offset + 1)} - {fmtNumber(Math.min(offset + limit, data?.total ?? 0))}
          </span>
          <button disabled={offset + limit >= (data?.total ?? 0)} onClick={() => page(1)}>下一页</button>
        </div>
      </section>
    </div>
  );
}
