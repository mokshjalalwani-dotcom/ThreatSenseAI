import React, { useState, useRef, useCallback } from 'react'

// ── Constants ──────────────────────────────────────────────────────────────────

const API_BASE = import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000'

const ARTIFACT_TYPES = [
  { id: 'url',     label: 'URL',     icon: '🔗', binary: false },
  { id: 'email',   label: 'Email',   icon: '📧', binary: false },
  { id: 'sms',     label: 'SMS',     icon: '💬', binary: false },
  { id: 'webpage', label: 'Webpage', icon: '🌐', binary: true  },
  { id: 'image',   label: 'Image',   icon: '🖼️', binary: true  },
  { id: 'qr',      label: 'QR Code', icon: '⬛', binary: true  },
  { id: 'file',    label: 'File',    icon: '📁', binary: true  },
]

const SEV_ORDER = { critical: 5, high: 4, medium: 3, low: 2, info: 1 }

const VERDICT_COLOR = {
  malicious:        '#ef4444',
  likely_malicious: '#f97316',
  suspicious:       '#f59e0b',
  safe:             '#22c55e',
  unknown:          '#6b7280',
  error:            '#ef4444',
}

// ── Helpers ────────────────────────────────────────────────────────────────────

function scoreColor(s) {
  if (s >= 75) return '#ef4444'
  if (s >= 50) return '#f97316'
  if (s >= 25) return '#f59e0b'
  return '#22c55e'
}

function domainBarColor(s) {
  if (s >= 0.75) return '#ef4444'
  if (s >= 0.5)  return '#f97316'
  if (s >= 0.25) return '#f59e0b'
  return '#22c55e'
}

function ScoreRing({ score }) {
  const r = 38
  const circ = 2 * Math.PI * r
  const dash = ((score || 0) / 100) * circ
  const color = scoreColor(score || 0)

  return (
    <div className="score-ring">
      <svg width="100" height="100" viewBox="0 0 100 100">
        <circle cx="50" cy="50" r={r} fill="none" stroke="#1e293b" strokeWidth="8"/>
        <circle
          cx="50" cy="50" r={r} fill="none"
          stroke={color} strokeWidth="8"
          strokeDasharray={`${dash} ${circ}`}
          strokeLinecap="round"
          style={{ transition: 'stroke-dasharray 0.8s cubic-bezier(0.4,0,0.2,1)' }}
        />
      </svg>
      <div className="score-center">
        <span className="score-num" style={{ color }}>{Math.round(score || 0)}</span>
        <span className="score-label">risk</span>
      </div>
    </div>
  )
}

function VerdictBadge({ verdict }) {
  const icons = {
    malicious: '🔴', likely_malicious: '🟠', suspicious: '🟡', safe: '🟢', unknown: '⚫',
  }
  return (
    <span className={`verdict-badge ${verdict || 'unknown'}`}>
      {icons[verdict] || '⚫'} {(verdict || 'unknown').replace('_', ' ')}
    </span>
  )
}

function EvidenceItem({ ev }) {
  const sev = ev.severity?.toLowerCase() || 'info'
  return (
    <div className="evidence-item">
      <div className={`sev-dot ${sev}`} title={sev} />
      <div className="evidence-body">
        <div className="evidence-desc">{ev.description}</div>
        <div className="evidence-meta">
          {ev.source_engine && <span className="badge engine">{ev.source_engine}</span>}
          {ev.rule_id && <span className="badge">{ev.rule_id}</span>}
          {ev.matched_text && (
            <span className="badge" style={{ fontFamily: 'monospace', maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis' }}>
              "{ev.matched_text.slice(0, 40)}"
            </span>
          )}
        </div>
      </div>
    </div>
  )
}

function DomainBreakdown({ domains }) {
  if (!domains?.length) return null
  return (
    <div className="section">
      <div className="section-header">
        <div className="section-icon">🗂️</div>
        Domain Breakdown
      </div>
      {domains.map(d => (
        <div className="domain-row" key={d.domain_id}>
          <div className="domain-name">{d.domain_name}</div>
          <div className="domain-bar-wrap">
            <div className="domain-bar-bg">
              <div
                className="domain-bar-fill"
                style={{
                  width: `${(d.score * 100).toFixed(1)}%`,
                  background: domainBarColor(d.score),
                }}
              />
            </div>
          </div>
          <div className="domain-score" style={{ color: domainBarColor(d.score) }}>
            {(d.score * 100).toFixed(0)}
          </div>
        </div>
      ))}
    </div>
  )
}

// ── Main App ───────────────────────────────────────────────────────────────────

export default function App() {
  const [artifactType, setArtifactType] = useState('url')
  const [content, setContent] = useState('')
  const [file, setFile] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [report, setReport] = useState(null)
  const [drag, setDrag] = useState(false)
  const fileRef = useRef()

  const isBinary = ARTIFACT_TYPES.find(t => t.id === artifactType)?.binary

  const handleTypeChange = (id) => {
    setArtifactType(id)
    setContent('')
    setFile(null)
    setError(null)
  }

  const handleFile = (f) => {
    if (!f) return
    setFile(f)
  }

  const handleDrop = useCallback((e) => {
    e.preventDefault()
    setDrag(false)
    const f = e.dataTransfer.files[0]
    if (f) handleFile(f)
  }, [])

  const handleSubmit = async (e) => {
    e.preventDefault()
    setError(null)
    setLoading(true)
    setReport(null)

    try {
      let resp
      if (isBinary && file) {
        const fd = new FormData()
        fd.append('type', artifactType)
        fd.append('file', file)
        resp = await fetch(`${API_BASE}/analyze`, { method: 'POST', body: fd })
      } else {
        resp = await fetch(`${API_BASE}/analyze`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ type: artifactType, raw_content: content }),
        })
      }

      if (!resp.ok) {
        const err = await resp.json().catch(() => ({ detail: resp.statusText }))
        throw new Error(err.detail || `HTTP ${resp.status}`)
      }

      const data = await resp.json()
      setReport(data)
    } catch (err) {
      if (err.message.includes('Failed to fetch')) {
        setError(
          `Network Error: Could not connect to API at ${API_BASE}.\n\n` +
          `• If running locally: ensure the backend is running via 'uvicorn app.main:app --reload'.\n` +
          `• If deployed on Render: your backend URL might be different from the default. Check your Render Dashboard for the backend Web Service URL and set it as VITE_API_URL in the frontend Static Site environment variables.`
        )
      } else {
        setError(err.message)
      }
    } finally {
      setLoading(false)
    }
  }

  const sortedEvidence = report?.top_evidence
    ? [...report.top_evidence].sort((a, b) =>
        (SEV_ORDER[b.severity?.toLowerCase()] || 0) - (SEV_ORDER[a.severity?.toLowerCase()] || 0)
      )
    : []

  return (
    <div className="app">
      {/* Header */}
      <header className="header">
        <div className="header-logo">🛡️</div>
        <h1>ThreatSense AI</h1>
        <span className="header-sub">Multi-layer Cybersecurity Analysis · 22 detectors · 5 domains</span>
      </header>

      <div className="main">
        {/* ── Left panel: form ── */}
        <div className="panel-left">
          <div className="form-title">🔍 Analyse an Artifact</div>

          {/* Artifact type selector */}
          <div className="type-grid">
            {ARTIFACT_TYPES.map(t => (
              <button
                key={t.id}
                className={`type-btn ${artifactType === t.id ? 'active' : ''}`}
                onClick={() => handleTypeChange(t.id)}
              >
                <div style={{ fontSize: 16 }}>{t.icon}</div>
                <div>{t.label}</div>
              </button>
            ))}
          </div>

          <form onSubmit={handleSubmit}>
            {isBinary ? (
              <div className="input-group">
                <label>Upload File</label>
                <div
                  className={`file-drop ${drag ? 'drag-over' : ''}`}
                  onDragOver={(e) => { e.preventDefault(); setDrag(true) }}
                  onDragLeave={() => setDrag(false)}
                  onDrop={handleDrop}
                  onClick={() => fileRef.current?.click()}
                >
                  <input
                    ref={fileRef}
                    type="file"
                    onChange={e => handleFile(e.target.files[0])}
                    style={{ display: 'none' }}
                  />
                  <div className="icon">{file ? '✅' : '📂'}</div>
                  <div>{file ? file.name : 'Drop file here or click to browse'}</div>
                  {file && (
                    <div className="hint">
                      {(file.size / 1024).toFixed(1)} KB · {file.type || 'unknown type'}
                    </div>
                  )}
                  {!file && <div className="hint">Max 10 MB · Images, EML, HTML, PDF…</div>}
                </div>
              </div>
            ) : (
              <div className="input-group">
                <label>
                  {artifactType === 'url' ? 'URL to analyse' :
                   artifactType === 'email' ? 'Paste RFC 822 email (raw .eml)' :
                   'Message content'}
                </label>
                <textarea
                  rows={artifactType === 'email' ? 12 : 4}
                  placeholder={
                    artifactType === 'url' ? 'https://example.com' :
                    artifactType === 'email' ? 'From: sender@example.com\nTo: ...\nSubject: ...\n\nEmail body here…' :
                    'Paste SMS or message content…'
                  }
                  value={content}
                  onChange={e => setContent(e.target.value)}
                />
              </div>
            )}

            <button
              type="submit"
              className="submit-btn"
              disabled={loading || (isBinary ? !file : !content.trim())}
            >
              {loading ? <><div className="spinner" /> Analysing…</> : <>🛡️ Analyse Artifact</>}
            </button>
          </form>

          {/* Quick tips */}
          {!report && !loading && (
            <div style={{ marginTop: 24, color: 'var(--text-muted)', fontSize: 12, lineHeight: 1.8 }}>
              <div style={{ fontWeight: 600, marginBottom: 8, color: 'var(--text)' }}>💡 Try these examples:</div>
              <div style={{ cursor: 'pointer', padding: '4px 0' }}
                onClick={() => { setArtifactType('url'); setContent('http://secure-paypal-login.xyz/verify?token=abc123') }}>
                → Fake PayPal login URL
              </div>
              <div style={{ cursor: 'pointer', padding: '4px 0' }}
                onClick={() => { setArtifactType('sms'); setContent('URGENT: Your SBI account is blocked. Verify OTP at http://sbi-secure.xyz immediately or account will be closed.') }}>
                → SBI smishing SMS
              </div>
              <div style={{ cursor: 'pointer', padding: '4px 0' }}
                onClick={() => { setArtifactType('sms'); setContent('Hi Bob, see you at the meeting tomorrow at 10am. — Alice') }}>
                → Safe message (baseline)
              </div>
            </div>
          )}
        </div>

        {/* ── Right panel: results ── */}
        <div className="panel-right">
          {error && (
            <div className="error-box" style={{ whiteSpace: 'pre-wrap' }}>
              ⚠️ <strong>Analysis failed:</strong><br />{error}
            </div>
          )}

          {!report && !loading && !error && (
            <div className="placeholder">
              <div className="big-icon">🛡️</div>
              <p>Submit an artifact to see a full multi-layer threat analysis report.</p>
              <p style={{ fontSize: 11, opacity: 0.6 }}>22 detectors · 5 domains · NLP + URL + DOM + Email + QR</p>
            </div>
          )}

          {loading && (
            <div className="placeholder">
              <div className="big-icon">⏳</div>
              <p>Running 22 detectors across 5 threat domains…</p>
              <p style={{ fontSize: 11, opacity: 0.6 }}>NLP engine · URL analysis · Intel lookup</p>
            </div>
          )}

          {report && !loading && (
            <div style={{ animation: 'fadeIn 0.3s ease' }}>
              {/* Risk header */}
              <div className="risk-header">
                <ScoreRing score={report.risk_score} />
                <div className="verdict-block">
                  <VerdictBadge verdict={report.verdict} />
                  {report.primary_threat_type && (
                    <div className="primary-threat">{report.primary_threat_type}</div>
                  )}
                  <div className="confidence-row">
                    Confidence: {((report.confidence || 0) * 100).toFixed(0)}% ·
                    Backend: <strong>{report.nlp_backend_used || 'rules'}</strong>
                  </div>
                  {report.secondary_tags?.length > 0 && (
                    <div className="tag-row">
                      {report.secondary_tags.map(t => (
                        <span key={t} className="tag">{t}</span>
                      ))}
                    </div>
                  )}
                </div>
              </div>

              {/* Domain breakdown */}
              <DomainBreakdown domains={report.per_domain_scores} />

              {/* Evidence */}
              {sortedEvidence.length > 0 && (
                <div className="section">
                  <div className="section-header">
                    <div className="section-icon">🔎</div>
                    Top Evidence ({sortedEvidence.length})
                  </div>
                  {sortedEvidence.map((ev, i) => (
                    <EvidenceItem key={i} ev={ev} />
                  ))}
                </div>
              )}

              {/* Recommended actions */}
              {report.recommended_actions?.length > 0 && (
                <div className="section">
                  <div className="section-header">
                    <div className="section-icon">💡</div>
                    Recommended Actions
                  </div>
                  {report.recommended_actions.map((a, i) => (
                    <div key={i} className="action-item">{a}</div>
                  ))}
                </div>
              )}

              {/* Errors / skipped */}
              {(report.errors?.length > 0 || report.skipped_components?.length > 0) && (
                <div className="section" style={{ opacity: 0.7 }}>
                  <div className="section-header">
                    <div className="section-icon">⚙️</div>
                    Pipeline Metadata
                  </div>
                  {report.errors?.length > 0 && (
                    <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 6 }}>
                      Errors: {report.errors.join(', ')}
                    </div>
                  )}
                  {report.skipped_components?.length > 0 && (
                    <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                      Skipped: {report.skipped_components.join(', ')}
                    </div>
                  )}
                  <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 6 }}>
                    Analysis ID: <code style={{ fontFamily: 'monospace' }}>{report.analysis_id}</code>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
