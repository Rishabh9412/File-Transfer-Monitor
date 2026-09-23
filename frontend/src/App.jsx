import { useState, useEffect, useCallback } from 'react'

const API = 'https://file-transfer-monitor.onrender.com/api'

function App() {
  const [logs, setLogs] = useState([])
  const [alerts, setAlerts] = useState([])
  const [summary, setSummary] = useState({ total_alerts: 0, by_type: {} })
  const [connected, setConnected] = useState(false)
  const [simulating, setSimulating] = useState(false)
  const [report, setReport] = useState(null)
  const [toast, setToast] = useState(null)
  const [refreshing, setRefreshing] = useState(false)
  const [lastUpdated, setLastUpdated] = useState(null)

  const fetchData = useCallback(async () => {
    try {
      const [logsRes, alertsRes, summaryRes] = await Promise.all([
        fetch(`${API}/logs`),
        fetch(`${API}/alerts`),
        fetch(`${API}/alerts/summary`)
      ])
      setLogs(await logsRes.json())
      setAlerts(await alertsRes.json())
      setSummary(await summaryRes.json())
      setConnected(true)
      setLastUpdated(new Date())
    } catch {
      setConnected(false)
    }
  }, [])

  useEffect(() => {
    fetchData()
    const interval = setInterval(fetchData, 3000)
    return () => clearInterval(interval)
  }, [fetchData])

  const handleSimulate = async () => {
    setSimulating(true)
    try {
      await fetch(`${API}/simulate`, { method: 'POST' })
      await fetchData()
    } catch {
      setConnected(false)
    }
    setSimulating(false)
  }

  const handleReport = async () => {
    const res = await fetch(`${API}/report`, { method: 'POST' })
    const data = await res.json()
    setReport(data)
    setToast('Audit report generated — saved to backend/logs/audit_report.json')
    setTimeout(() => setToast(null), 4000)
  }

  const handleManualRefresh = async () => {
    setRefreshing(true)
    await fetchData()
    setTimeout(() => setRefreshing(false), 400)
  }

  const sensitiveCount = logs.filter(l => l.status !== 'normal').length

  return (
    <div className="app">
      {toast && (
        <div style={{
          position: 'fixed', top: 20, right: 20, background: '#1d3a2a',
          border: '1px solid #4ade80', color: '#4ade80', padding: '12px 20px',
          borderRadius: 8, fontSize: 13, zIndex: 1000, boxShadow: '0 4px 12px rgba(0,0,0,0.4)'
        }}>
          {toast}
        </div>
      )}

      <div className="header">
        <h1>Secure File Transfer Monitoring System</h1>
        <div className="status">
          <span className="dot" style={{ background: connected ? '#4ade80' : '#f87171', boxShadow: connected ? '0 0 6px #4ade80' : '0 0 6px #f87171' }}></span>
          {connected ? 'Monitoring active' : 'Backend disconnected'}
        </div>
      </div>

      <div className="stats-grid">
        <div className="stat-card">
          <div className="label">Total events</div>
          <div className="value">{logs.length}</div>
        </div>
        <div className="stat-card danger">
          <div className="label">Active alerts</div>
          <div className="value">{summary.total_alerts}</div>
        </div>
        <div className="stat-card warning">
          <div className="label">Flagged events</div>
          <div className="value">{sensitiveCount}</div>
        </div>
        <div className="stat-card success">
          <div className="label">Status</div>
          <div className="value" style={{ fontSize: 16 }}>{connected ? 'Online' : 'Offline'}</div>
        </div>
      </div>

      <div className="actions">
        <button className="btn primary" onClick={handleSimulate} disabled={simulating}>
          {simulating ? 'Simulating...' : 'Simulate Activity'}
        </button>
        <button className="btn" onClick={handleReport}>Generate Audit Report</button>
        <button className="btn" onClick={handleManualRefresh} disabled={refreshing}>
          {refreshing ? 'Refreshing...' : 'Refresh Now'}
        </button>
      </div>

      {lastUpdated && (
        <div style={{ fontSize: 12, color: '#7d8590', marginBottom: 20, marginTop: -12 }}>
          Last updated: {lastUpdated.toLocaleTimeString()}
        </div>
      )}

      <div className="panel">
        <div className="panel-header">Active alerts ({alerts.length})</div>
        {alerts.length === 0 ? (
          <div className="empty">No alerts — system clean</div>
        ) : (
          <table>
            <thead>
              <tr><th>Time</th><th>Event</th><th>Source</th><th>Status</th></tr>
            </thead>
            <tbody>
              {alerts.slice(0, 10).map((a, i) => (
                <tr key={i}>
                  <td>{new Date(a.timestamp).toLocaleTimeString()}</td>
                  <td>{a.event_type}</td>
                  <td>{a.source?.split('\\').pop()}</td>
                  <td><span className={`badge ${a.status}`}>{a.status}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <div className="panel">
        <div className="panel-header">Event log ({logs.length})</div>
        {logs.length === 0 ? (
          <div className="empty">No events yet — try Simulate Activity</div>
        ) : (
          <table>
            <thead>
              <tr><th>Time</th><th>Event</th><th>Source</th><th>User</th><th>Status</th></tr>
            </thead>
            <tbody>
              {logs.slice(0, 20).map((l, i) => (
                <tr key={i}>
                  <td>{new Date(l.timestamp).toLocaleTimeString()}</td>
                  <td>{l.event_type}</td>
                  <td>{l.source?.split('\\').pop()}</td>
                  <td>{l.user}</td>
                  <td><span className={`badge ${l.status}`}>{l.status}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {report && (
        <div className="panel">
          <div className="panel-header">Audit report — generated {new Date(report.generated_at).toLocaleTimeString()}</div>
          <div style={{ padding: '16px 18px' }}>
            <p style={{ marginBottom: 10 }}>Total events: <strong>{report.total_events}</strong></p>
            <p style={{ marginBottom: 10 }}>Total alerts: <strong style={{ color: '#f87171' }}>{report.total_alerts}</strong></p>
            <p style={{ marginBottom: 10 }}>Event breakdown:</p>
            <ul style={{ marginLeft: 20, marginBottom: 10 }}>
              {Object.entries(report.event_counts).map(([type, count]) => (
                <li key={type}>{type}: {count}</li>
              ))}
            </ul>
            <p style={{ marginBottom: 10 }}>Alert breakdown:</p>
            <ul style={{ marginLeft: 20 }}>
              {Object.entries(report.alert_breakdown).map(([type, count]) => (
                <li key={type}>{type}: {count}</li>
              ))}
            </ul>
          </div>
        </div>
      )}
    </div>
  )
}

export default App