import React, { useState, useEffect } from 'react';
import {
  Shield,
  AlertTriangle,
  Flame,
  Activity,
  Shuffle,
  FileSpreadsheet,
  Download,
  Upload,
  RefreshCw,
  Search,
  Sliders,
  CheckCircle2,
  XCircle,
  X,
  ChevronRight,
  ExternalLink,
  Info,
  Server,
  Filter,
  Lock,
  ArrowUpDown
} from 'lucide-react';

const API_BASE = 'http://localhost:8000';

export default function App() {
  const [assessment, setAssessment] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [activeTab, setActiveTab] = useState('triage'); // 'triage', 'baseline', 'quarantine', 'config'
  const [selectedEntity, setSelectedEntity] = useState(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [bandFilter, setBandFilter] = useState('all');
  const [sortField, setSortField] = useState('risk_score');
  const [sortAsc, setSortAsc] = useState(false);

  // Scoring config state
  const [ruleWeight, setRuleWeight] = useState(0.60);
  const [anomalyWeight, setAnomalyWeight] = useState(0.40);
  const [randomSeed, setRandomSeed] = useState(42);
  const [reviewRate, setReviewRate] = useState(0.25);
  const [rescoring, setRescoring] = useState(false);

  useEffect(() => {
    fetchAssessment();
  }, []);

  const fetchAssessment = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`${API_BASE}/api/assessment/latest`);
      if (!res.ok) throw new Error(`Server returned ${res.status}`);
      const data = await res.json();
      setAssessment(data);
      if (data.scoring_config) {
        setRuleWeight(data.scoring_config.rule_weight ?? 0.60);
        setAnomalyWeight(data.scoring_config.anomaly_weight ?? 0.40);
        setRandomSeed(data.scoring_config.random_seed ?? 42);
        setReviewRate(data.scoring_config.baseline_review_rate ?? 0.25);
      }
    } catch (err) {
      console.error(err);
      setError('Failed to connect to backend assessment API. Ensure the Python API is running on localhost:8000.');
    } finally {
      setLoading(false);
    }
  };

  const handleRescore = async () => {
    setRescoring(true);
    try {
      const res = await fetch(`${API_BASE}/api/assessment/run`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          rule_weight: parseFloat(ruleWeight),
          anomaly_weight: parseFloat(anomalyWeight),
          random_seed: parseInt(randomSeed, 10),
          baseline_review_rate: parseFloat(reviewRate),
        }),
      });
      if (!res.ok) throw new Error(`Rescore failed: ${res.status}`);
      const data = await res.json();
      setAssessment(data);
    } catch (err) {
      alert('Error triggering re-assessment: ' + err.message);
    } finally {
      setRescoring(false);
    }
  };

  const handleFileUpload = async (e) => {
    const file = e.target.files[0];
    if (!file) return;
    const formData = new FormData();
    formData.append('file', file);

    setLoading(true);
    try {
      const res = await fetch(`${API_BASE}/api/assessment/upload?rule_weight=${ruleWeight}&anomaly_weight=${anomalyWeight}&random_seed=${randomSeed}&baseline_review_rate=${reviewRate}`, {
        method: 'POST',
        body: formData,
      });
      if (!res.ok) throw new Error(`Upload assessment failed: ${res.status}`);
      const data = await res.json();
      setAssessment(data);
      alert(`Successfully loaded and assessed ${data.total_entities_evaluated} entities from ${file.name}`);
    } catch (err) {
      alert('File upload error: ' + err.message);
    } finally {
      setLoading(false);
      e.target.value = '';
    }
  };

  // Filtered and sorted entities
  const filteredEntities = (assessment?.entities || []).filter((entity) => {
    const matchSearch = entity.entity_id.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (entity.entity_type && entity.entity_type.toLowerCase().includes(searchQuery.toLowerCase()));
    const matchBand = bandFilter === 'all' || entity.risk_band === bandFilter;
    return matchSearch && matchBand;
  }).sort((a, b) => {
    let valA = a[sortField];
    let valB = b[sortField];
    if (typeof valA === 'string') valA = valA.toLowerCase();
    if (typeof valB === 'string') valB = valB.toLowerCase();
    if (valA < valB) return sortAsc ? -1 : 1;
    if (valA > valB) return sortAsc ? 1 : -1;
    return 0;
  });

  const getScoreBadgeClass = (band) => {
    switch (band) {
      case 'critical': return 'score-badge badge-critical';
      case 'high': return 'score-badge badge-high';
      case 'medium': return 'score-badge badge-medium';
      default: return 'score-badge badge-low';
    }
  };

  const highCriticalCount = (assessment?.risk_band_counts?.critical || 0) + (assessment?.risk_band_counts?.high || 0);

  return (
    <div className="app-container">
      {/* Top Navbar */}
      <header className="top-navbar">
        <div className="brand-section">
          <div style={{ background: 'rgba(99, 102, 241, 0.2)', padding: '0.5rem', borderRadius: '8px', border: '1px solid rgba(99,102,241,0.4)' }}>
            <Shield size={24} color="#06b6d4" />
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <span className="brand-title">P-006 Risk Scoring Assessment</span>
              <span className="brand-badge">PROD-ASSESSMENT</span>
            </div>
            <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
              Isolation Forest + Rule Signal Extraction Engine (5–50 Scale)
            </p>
          </div>
        </div>

        <div className="nav-actions">
          <label className="btn btn-outline btn-sm" style={{ cursor: 'pointer' }}>
            <Upload size={14} /> Upload Logs (.csv/.json)
            <input type="file" accept=".csv,.json" onChange={handleFileUpload} style={{ display: 'none' }} />
          </label>

          <a href={`${API_BASE}/api/assessment/export/csv`} className="btn btn-outline btn-sm">
            <FileSpreadsheet size={14} /> Export CSV
          </a>

          <a href={`${API_BASE}/api/assessment/export/json`} className="btn btn-outline btn-sm">
            <Download size={14} /> Export JSON
          </a>

          <button onClick={fetchAssessment} className="btn btn-primary btn-sm" disabled={loading}>
            <RefreshCw size={14} className={loading ? 'spin' : ''} /> Refresh
          </button>
        </div>
      </header>

      {/* Main Container */}
      <main className="main-content">
        {error && (
          <div style={{ background: 'rgba(239, 68, 68, 0.15)', border: '1px solid rgba(239, 68, 68, 0.4)', borderRadius: '8px', padding: '1rem', marginBottom: '1.5rem', display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <AlertTriangle color="#ef4444" size={20} />
            <div>
              <strong>Service Connectivity Alert:</strong> {error}
            </div>
          </div>
        )}

        {/* KPI Banner */}
        <div className="kpi-grid">
          <div className="kpi-card">
            <div className="kpi-header">
              <span>TOTAL SCORED ENTITIES</span>
              <Activity size={16} color="var(--accent-cyan)" />
            </div>
            <div className="kpi-value">{assessment?.total_entities_evaluated ?? '—'}</div>
            <div className="kpi-subtitle">Active principals in window</div>
          </div>

          <div className="kpi-card" style={{ borderLeft: '3px solid var(--risk-critical)' }}>
            <div className="kpi-header">
              <span>HIGH & CRITICAL THREATS</span>
              <Flame size={16} color="var(--risk-critical)" />
            </div>
            <div className="kpi-value" style={{ color: highCriticalCount > 0 ? '#f87171' : 'var(--text-primary)' }}>
              {highCriticalCount}
            </div>
            <div className="kpi-subtitle">
              Crit: {assessment?.risk_band_counts?.critical || 0} | High: {assessment?.risk_band_counts?.high || 0}
            </div>
          </div>

          <div className="kpi-card">
            <div className="kpi-header">
              <span>RANDOM BASELINE OVERLAP</span>
              <Shuffle size={16} color="var(--accent-indigo)" />
            </div>
            <div className="kpi-value">
              {assessment?.baseline_comparison ? `${(assessment.baseline_comparison.overlap_ratio * 100).toFixed(0)}%` : '—'}
            </div>
            <div className="kpi-subtitle">
              {assessment?.baseline_comparison?.overlap_count || 0} / {assessment?.baseline_comparison?.ml_high_risk_count || 0} high-risk overlap (Seed: {assessment?.baseline_comparison?.seed || 42})
            </div>
          </div>

          <div className="kpi-card">
            <div className="kpi-header">
              <span>DATA VALIDATION & QUARANTINE</span>
              <Server size={16} color="#10b981" />
            </div>
            <div className="kpi-value" style={{ color: (assessment?.validation_summary?.quarantined_rows_count || 0) > 0 ? '#facc15' : '#10b981' }}>
              {assessment?.validation_summary?.quarantined_rows_count ?? 0}
            </div>
            <div className="kpi-subtitle">
              {assessment?.validation_summary?.valid_rows_count || 0} valid events processed
            </div>
          </div>
        </div>

        {/* Tab Navigation */}
        <div className="tabs-container">
          <button
            className={`tab-btn ${activeTab === 'triage' ? 'active' : ''}`}
            onClick={() => setActiveTab('triage')}
          >
            <Shield size={16} /> Entity Triage & Rankings
          </button>
          <button
            className={`tab-btn ${activeTab === 'baseline' ? 'active' : ''}`}
            onClick={() => setActiveTab('baseline')}
          >
            <Shuffle size={16} /> Baseline Comparison (ML vs. Random)
          </button>
          <button
            className={`tab-btn ${activeTab === 'quarantine' ? 'active' : ''}`}
            onClick={() => setActiveTab('quarantine')}
          >
            <AlertTriangle size={16} /> Quarantine & Row Inspector ({assessment?.validation_summary?.quarantined_rows_count || 0})
          </button>
          <button
            className={`tab-btn ${activeTab === 'config' ? 'active' : ''}`}
            onClick={() => setActiveTab('config')}
          >
            <Sliders size={16} /> Scoring Weights & Hyperparameters
          </button>
        </div>

        {/* Tab 1: Entity Triage */}
        {activeTab === 'triage' && (
          <div className="glass-panel">
            <div className="panel-header">
              <div className="panel-title">
                <span>Ranked Risk Assessment (Range: 5.0 – 50.0)</span>
                <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)', fontWeight: 400 }}>
                  ({filteredEntities.length} entities shown)
                </span>
              </div>

              <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'center', flexWrap: 'wrap' }}>
                <div style={{ position: 'relative', minWidth: '220px' }}>
                  <Search size={14} style={{ position: 'absolute', left: '10px', top: '10px', color: 'var(--text-muted)' }} />
                  <input
                    type="text"
                    placeholder="Search entity ID or type..."
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    style={{
                      width: '100%',
                      padding: '0.45rem 0.5rem 0.45rem 2rem',
                      background: 'var(--bg-tertiary)',
                      border: '1px solid var(--border-subtle)',
                      borderRadius: '6px',
                      color: 'white',
                      fontSize: '0.85rem',
                    }}
                  />
                </div>

                <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                  <Filter size={14} color="var(--text-muted)" />
                  <select
                    value={bandFilter}
                    onChange={(e) => setBandFilter(e.target.value)}
                    style={{
                      background: 'var(--bg-tertiary)',
                      border: '1px solid var(--border-subtle)',
                      color: 'white',
                      padding: '0.45rem 0.75rem',
                      borderRadius: '6px',
                      fontSize: '0.85rem',
                    }}
                  >
                    <option value="all">All Risk Bands</option>
                    <option value="critical">Critical (42–50)</option>
                    <option value="high">High (30–41)</option>
                    <option value="medium">Medium (15–29)</option>
                    <option value="low">Low (5–14)</option>
                  </select>
                </div>
              </div>
            </div>

            <div className="table-wrapper">
              <table className="soc-table">
                <thead>
                  <tr>
                    <th onClick={() => { setSortField('entity_id'); setSortAsc(!sortAsc); }} style={{ cursor: 'pointer' }}>
                      Entity Identifier {sortField === 'entity_id' && (sortAsc ? '▲' : '▼')}
                    </th>
                    <th>Type</th>
                    <th onClick={() => { setSortField('risk_score'); setSortAsc(!sortAsc); }} style={{ cursor: 'pointer' }}>
                      Dynamic Risk Score (5–50) {sortField === 'risk_score' && (sortAsc ? '▲' : '▼')}
                    </th>
                    <th>Risk Band</th>
                    <th>Rule Signal</th>
                    <th>Anomaly Signal</th>
                    <th>Random Baseline?</th>
                    <th>Top Contributor</th>
                    <th>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredEntities.length === 0 ? (
                    <tr>
                      <td colSpan={9} style={{ textAlign: 'center', padding: '2.5rem', color: 'var(--text-muted)' }}>
                        No entities match the current search or risk band filter.
                      </td>
                    </tr>
                  ) : (
                    filteredEntities.map((entity) => (
                      <tr key={entity.entity_id} onClick={() => setSelectedEntity(entity)}>
                        <td>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontWeight: 600 }}>
                            <span style={{ color: entity.risk_band === 'critical' ? 'var(--risk-critical)' : 'var(--text-primary)' }}>
                              {entity.entity_id}
                            </span>
                          </div>
                        </td>
                        <td>
                          <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontFamily: 'var(--font-mono)' }}>
                            {entity.entity_type}
                          </span>
                        </td>
                        <td>
                          <div className={getScoreBadgeClass(entity.risk_band)}>
                            <Flame size={13} />
                            <span>{entity.risk_score.toFixed(2)}</span>
                          </div>
                        </td>
                        <td>
                          <span style={{ textTransform: 'capitalize', fontWeight: 600, fontSize: '0.85rem' }}>
                            {entity.risk_band}
                          </span>
                        </td>
                        <td>
                          <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
                            {entity.rule_score.toFixed(1)} pts
                          </span>
                        </td>
                        <td>
                          <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
                            {entity.anomaly_score !== null ? `${(entity.anomaly_score * 100).toFixed(0)}%` : 'N/A'}
                          </span>
                        </td>
                        <td>
                          {entity.selected_by_random_baseline ? (
                            <span style={{ color: '#06b6d4', display: 'flex', alignItems: 'center', gap: '0.3rem', fontSize: '0.8rem', fontWeight: 600 }}>
                              <CheckCircle2 size={14} /> Selected
                            </span>
                          ) : (
                            <span style={{ color: 'var(--text-muted)', fontSize: '0.8rem' }}>No</span>
                          )}
                        </td>
                        <td>
                          <div style={{ maxWidth: '280px', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', fontSize: '0.85rem' }}>
                            {entity.top_contributors.length > 0 ? (
                              <span title={entity.top_contributors[0].description}>
                                {entity.top_contributors[0].rule_name} (+{entity.top_contributors[0].score_contribution})
                              </span>
                            ) : (
                              <span style={{ color: 'var(--text-muted)' }}>Unsupervised anomaly</span>
                            )}
                          </div>
                        </td>
                        <td>
                          <button
                            className="btn btn-outline btn-sm"
                            onClick={(e) => { e.stopPropagation(); setSelectedEntity(entity); }}
                          >
                            Inspect <ChevronRight size={12} />
                          </button>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Tab 2: Baseline Comparison */}
        {activeTab === 'baseline' && assessment?.baseline_comparison && (
          <div>
            <div className="glass-panel">
              <div className="panel-title" style={{ marginBottom: '1rem' }}>
                <Shuffle size={20} color="var(--accent-cyan)" />
                <span>ML Model & Rule Prioritization vs. Random Selection Baseline</span>
              </div>
              <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', marginBottom: '1.25rem' }}>
                {assessment.baseline_comparison.explanation}
              </p>

              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '1.25rem', marginBottom: '1.5rem' }}>
                <div style={{ background: 'var(--bg-tertiary)', padding: '1.25rem', borderRadius: '8px', border: '1px solid var(--border-subtle)' }}>
                  <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', fontWeight: 600 }}>ML & RULE CANDIDATES (HIGH/CRIT)</div>
                  <div style={{ fontSize: '1.8rem', fontWeight: 700, color: 'var(--risk-high)', margin: '0.5rem 0' }}>
                    {assessment.baseline_comparison.ml_high_risk_count} Entities
                  </div>
                  <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                    Prioritized through Isolation Forest anomaly scoring and pattern rules.
                  </div>
                </div>

                <div style={{ background: 'var(--bg-tertiary)', padding: '1.25rem', borderRadius: '8px', border: '1px solid var(--border-subtle)' }}>
                  <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', fontWeight: 600 }}>RANDOM SELECTION CANDIDATES</div>
                  <div style={{ fontSize: '1.8rem', fontWeight: 700, color: '#06b6d4', margin: '0.5rem 0' }}>
                    {assessment.baseline_comparison.baseline_selected_count} Entities
                  </div>
                  <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                    Selected randomly with seed {assessment.baseline_comparison.seed} ({assessment.baseline_comparison.review_rate * 100}% review rate).
                  </div>
                </div>

                <div style={{ background: 'var(--bg-tertiary)', padding: '1.25rem', borderRadius: '8px', border: '1px solid var(--border-subtle)' }}>
                  <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', fontWeight: 600 }}>CHANCE OVERLAP</div>
                  <div style={{ fontSize: '1.8rem', fontWeight: 700, color: '#a855f7', margin: '0.5rem 0' }}>
                    {assessment.baseline_comparison.overlap_count} Entities ({(assessment.baseline_comparison.overlap_ratio * 100).toFixed(0)}%)
                  </div>
                  <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                    Entities surfaced by chance in the random sample.
                  </div>
                </div>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.5rem' }}>
                <div>
                  <h4 style={{ fontSize: '0.95rem', fontWeight: 600, marginBottom: '0.75rem', color: 'var(--risk-high)' }}>
                    Prioritized by Predictive ML Model ({assessment.baseline_comparison.isolation_forest_selected.length})
                  </h4>
                  <div style={{ background: 'var(--bg-primary)', padding: '1rem', borderRadius: '8px', border: '1px solid var(--border-subtle)' }}>
                    {assessment.baseline_comparison.isolation_forest_selected.map((ent) => (
                      <div key={ent} style={{ display: 'flex', justifyContent: 'space-between', padding: '0.4rem 0', borderBottom: '1px solid var(--border-subtle)', fontSize: '0.85rem' }}>
                        <span style={{ fontWeight: 600 }}>{ent}</span>
                        {assessment.baseline_comparison.random_baseline_selected.includes(ent) ? (
                          <span style={{ color: '#06b6d4', fontSize: '0.75rem' }}>★ Also in Random</span>
                        ) : (
                          <span style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>ML Unique</span>
                        )}
                      </div>
                    ))}
                  </div>
                </div>

                <div>
                  <h4 style={{ fontSize: '0.95rem', fontWeight: 600, marginBottom: '0.75rem', color: '#06b6d4' }}>
                    Selected by Random Baseline ({assessment.baseline_comparison.random_baseline_selected.length})
                  </h4>
                  <div style={{ background: 'var(--bg-primary)', padding: '1rem', borderRadius: '8px', border: '1px solid var(--border-subtle)' }}>
                    {assessment.baseline_comparison.random_baseline_selected.map((ent) => (
                      <div key={ent} style={{ display: 'flex', justifyContent: 'space-between', padding: '0.4rem 0', borderBottom: '1px solid var(--border-subtle)', fontSize: '0.85rem' }}>
                        <span>{ent}</span>
                        {assessment.baseline_comparison.isolation_forest_selected.includes(ent) ? (
                          <span style={{ color: 'var(--risk-critical)', fontSize: '0.75rem', fontWeight: 600 }}>Matched ML Threat</span>
                        ) : (
                          <span style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>Benign Sample</span>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Tab 3: Quarantine & Row Inspector */}
        {activeTab === 'quarantine' && (
          <div className="glass-panel">
            <div className="panel-title" style={{ marginBottom: '1rem' }}>
              <AlertTriangle size={20} color="var(--risk-medium)" />
              <span>Input Validation & Row Quarantine Report</span>
            </div>
            <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', marginBottom: '1.25rem' }}>
              Invalid, corrupt, or unparseable input rows are quarantined to guarantee scoring resilience without crashing the pipeline.
            </p>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '1rem', marginBottom: '1.5rem' }}>
              <div style={{ background: 'var(--bg-tertiary)', padding: '1rem', borderRadius: '8px' }}>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>TOTAL ROWS INGESTED</div>
                <div style={{ fontSize: '1.5rem', fontWeight: 700 }}>{assessment?.validation_summary?.total_rows_read || 0}</div>
              </div>
              <div style={{ background: 'var(--bg-tertiary)', padding: '1rem', borderRadius: '8px' }}>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>VALID ROWS PROCESSED</div>
                <div style={{ fontSize: '1.5rem', fontWeight: 700, color: '#10b981' }}>{assessment?.validation_summary?.valid_rows_count || 0}</div>
              </div>
              <div style={{ background: 'var(--bg-tertiary)', padding: '1rem', borderRadius: '8px' }}>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>QUARANTINED ROWS</div>
                <div style={{ fontSize: '1.5rem', fontWeight: 700, color: 'var(--risk-medium)' }}>{assessment?.validation_summary?.quarantined_rows_count || 0}</div>
              </div>
            </div>

            {assessment?.validation_summary?.quarantined_details?.length > 0 ? (
              <div className="table-wrapper">
                <table className="soc-table">
                  <thead>
                    <tr>
                      <th>Row Index</th>
                      <th>Quarantine Reason</th>
                      <th>Missing Fields</th>
                      <th>Raw Record Preview</th>
                    </tr>
                  </thead>
                  <tbody>
                    {assessment.validation_summary.quarantined_details.map((q, i) => (
                      <tr key={i}>
                        <td style={{ fontFamily: 'var(--font-mono)' }}>#{q.row_index}</td>
                        <td style={{ color: '#fb923c', fontWeight: 500 }}>{q.reason}</td>
                        <td>
                          {q.missing_fields.length > 0 ? (
                            <span style={{ color: 'var(--risk-critical)', fontFamily: 'var(--font-mono)', fontSize: '0.8rem' }}>
                              {q.missing_fields.join(', ')}
                            </span>
                          ) : '—'}
                        </td>
                        <td>
                          <code style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', background: 'var(--bg-primary)', padding: '0.2rem 0.4rem', borderRadius: '4px' }}>
                            {JSON.stringify(q.raw_record)}
                          </code>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <div style={{ padding: '2rem', textAlign: 'center', color: '#10b981', background: 'var(--bg-tertiary)', borderRadius: '8px' }}>
                <CheckCircle2 size={32} style={{ margin: '0 auto 0.5rem auto' }} />
                <div>All ingested rows conformed 100% to schema. Zero rows quarantined.</div>
              </div>
            )}
          </div>
        )}

        {/* Tab 4: Scoring Weights & Hyperparameters */}
        {activeTab === 'config' && (
          <div className="glass-panel" style={{ maxWidth: '750px' }}>
            <div className="panel-title" style={{ marginBottom: '1rem' }}>
              <Sliders size={20} color="var(--accent-cyan)" />
              <span>Interactive What-If Scoring Configuration</span>
            </div>
            <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', marginBottom: '1.5rem' }}>
              Adjust relative weights between explainable rule signals and unsupervised Isolation Forest anomaly detection, or change the baseline seed.
            </p>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.5rem' }}>
                  <label style={{ fontWeight: 600, fontSize: '0.9rem' }}>Rule Signal Weight: {(ruleWeight * 100).toFixed(0)}%</label>
                  <span style={{ color: 'var(--text-muted)', fontSize: '0.8rem' }}>Domain Rule Catalog</span>
                </div>
                <input
                  type="range"
                  min="0.10"
                  max="0.90"
                  step="0.05"
                  value={ruleWeight}
                  onChange={(e) => {
                    const rw = parseFloat(e.target.value);
                    setRuleWeight(rw);
                    setAnomalyWeight(parseFloat((1.0 - rw).toFixed(2)));
                  }}
                  style={{ width: '100%' }}
                />
              </div>

              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.5rem' }}>
                  <label style={{ fontWeight: 600, fontSize: '0.9rem' }}>Isolation Forest Anomaly Weight: {(anomalyWeight * 100).toFixed(0)}%</label>
                  <span style={{ color: 'var(--text-muted)', fontSize: '0.8rem' }}>Unsupervised ML</span>
                </div>
                <input
                  type="range"
                  min="0.10"
                  max="0.90"
                  step="0.05"
                  value={anomalyWeight}
                  onChange={(e) => {
                    const aw = parseFloat(e.target.value);
                    setAnomalyWeight(aw);
                    setRuleWeight(parseFloat((1.0 - aw).toFixed(2)));
                  }}
                  style={{ width: '100%' }}
                />
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
                <div>
                  <label style={{ display: 'block', fontWeight: 600, fontSize: '0.85rem', marginBottom: '0.4rem' }}>
                    Random Selection Seed
                  </label>
                  <input
                    type="number"
                    value={randomSeed}
                    onChange={(e) => setRandomSeed(e.target.value)}
                    style={{
                      width: '100%',
                      padding: '0.5rem',
                      background: 'var(--bg-tertiary)',
                      border: '1px solid var(--border-subtle)',
                      borderRadius: '6px',
                      color: 'white',
                    }}
                  />
                </div>

                <div>
                  <label style={{ display: 'block', fontWeight: 600, fontSize: '0.85rem', marginBottom: '0.4rem' }}>
                    Baseline Review Rate (Fraction)
                  </label>
                  <input
                    type="number"
                    min="0.05"
                    max="1.0"
                    step="0.05"
                    value={reviewRate}
                    onChange={(e) => setReviewRate(e.target.value)}
                    style={{
                      width: '100%',
                      padding: '0.5rem',
                      background: 'var(--bg-tertiary)',
                      border: '1px solid var(--border-subtle)',
                      borderRadius: '6px',
                      color: 'white',
                    }}
                  />
                </div>
              </div>

              <button
                className="btn btn-primary"
                onClick={handleRescore}
                disabled={rescoring}
                style={{ justifyContent: 'center', marginTop: '0.5rem' }}
              >
                <RefreshCw size={16} className={rescoring ? 'spin' : ''} />
                {rescoring ? 'Re-scoring Pipeline...' : 'Re-calculate Dynamic Risk Scores'}
              </button>
            </div>
          </div>
        )}
      </main>

      {/* Entity Deep-Dive Drawer Modal */}
      {selectedEntity && (
        <div className="drawer-backdrop" onClick={() => setSelectedEntity(null)}>
          <div className="drawer-panel" onClick={(e) => e.stopPropagation()}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '1rem', marginBottom: '1.5rem' }}>
              <div>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', textTransform: 'uppercase' }}>
                  {selectedEntity.entity_type} PRINCIPAL
                </span>
                <h2 style={{ fontSize: '1.4rem', fontWeight: 700, color: 'var(--text-primary)' }}>
                  {selectedEntity.entity_id}
                </h2>
              </div>
              <button
                onClick={() => setSelectedEntity(null)}
                style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', padding: '0.25rem' }}
              >
                <X size={22} />
              </button>
            </div>

            {/* Score Summary Box */}
            <div style={{ background: 'var(--bg-tertiary)', borderRadius: '8px', padding: '1.25rem', border: '1px solid var(--border-subtle)', marginBottom: '1.5rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem' }}>
                <span style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>Normalized Dynamic Risk Score</span>
                <div className={getScoreBadgeClass(selectedEntity.risk_band)}>
                  <Flame size={14} />
                  <span>{selectedEntity.risk_score.toFixed(2)} / 50.0</span>
                </div>
              </div>

              <div style={{ background: 'var(--bg-primary)', height: '8px', borderRadius: '4px', overflow: 'hidden', marginBottom: '0.75rem' }}>
                <div
                  style={{
                    height: '100%',
                    width: `${((selectedEntity.risk_score - 5.0) / 45.0) * 100}%`,
                    background: selectedEntity.risk_band === 'critical' ? 'var(--risk-critical)' : (selectedEntity.risk_band === 'high' ? 'var(--risk-high)' : 'var(--accent-cyan)'),
                  }}
                />
              </div>

              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                <span>Rule Score: {selectedEntity.rule_score.toFixed(1)} pts</span>
                <span>Anomaly Intensity: {selectedEntity.anomaly_score !== null ? `${(selectedEntity.anomaly_score * 100).toFixed(0)}%` : 'N/A'}</span>
                <span>Band: {selectedEntity.risk_band.toUpperCase()}</span>
              </div>
            </div>

            {/* Contributing Rules & Patterns */}
            <h3 style={{ fontSize: '1rem', fontWeight: 600, marginBottom: '0.75rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <AlertTriangle size={16} color="var(--risk-high)" /> Top Contributing Rules & Patterns
            </h3>

            {selectedEntity.top_contributors.length > 0 ? (
              <div style={{ marginBottom: '1.5rem' }}>
                {selectedEntity.top_contributors.map((c, idx) => (
                  <div key={idx} className={`contributor-item ${c.severity === 'critical' ? 'crit' : (c.severity === 'high' ? 'high' : 'med')}`}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.35rem' }}>
                      <span style={{ fontWeight: 600, fontSize: '0.9rem' }}>{c.rule_name}</span>
                      <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem', fontWeight: 700, color: 'var(--text-primary)' }}>
                        +{c.score_contribution.toFixed(1)} pts
                      </span>
                    </div>
                    <p style={{ fontSize: '0.82rem', color: 'var(--text-secondary)' }}>{c.description}</p>
                  </div>
                ))}
              </div>
            ) : (
              <div style={{ background: 'var(--bg-tertiary)', padding: '1rem', borderRadius: '8px', color: 'var(--text-secondary)', fontSize: '0.85rem', marginBottom: '1.5rem' }}>
                No explicit rule triggers tripped. Risk score is derived predominantly from unsupervised Isolation Forest statistical isolation.
              </div>
            )}

            {/* Actionable Recommendations */}
            <h3 style={{ fontSize: '1rem', fontWeight: 600, marginBottom: '0.75rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <Lock size={16} color="var(--accent-cyan)" /> Actionable Analyst Recommendations
            </h3>

            <div style={{ marginBottom: '1.5rem' }}>
              {selectedEntity.recommendations.map((rec, idx) => (
                <div key={idx} className="rec-card">
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.35rem' }}>
                    <span style={{ fontWeight: 600, fontSize: '0.9rem', color: 'var(--text-primary)' }}>{rec.title}</span>
                    <span style={{ fontSize: '0.75rem', textTransform: 'uppercase', background: 'rgba(99,102,241,0.2)', padding: '0.15rem 0.45rem', borderRadius: '4px', color: '#818cf8' }}>
                      {rec.action_type.replace('_', ' ')}
                    </span>
                  </div>
                  <p style={{ fontSize: '0.82rem', color: 'var(--text-secondary)' }}>{rec.description}</p>
                </div>
              ))}
            </div>

            {/* Behavioral Feature Snapshot */}
            <h3 style={{ fontSize: '1rem', fontWeight: 600, marginBottom: '0.75rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <Activity size={16} color="var(--accent-indigo)" /> Behavioral Telemetry Metrics
            </h3>

            <div className="feature-grid">
              <div className="feature-cell">
                <div className="label">Total Activity Events</div>
                <div className="val">{selectedEntity.feature_summary?.total_events ?? 0}</div>
              </div>
              <div className="feature-cell">
                <div className="label">Failed Auth Attempts</div>
                <div className="val" style={{ color: (selectedEntity.feature_summary?.failed_login_count || 0) > 0 ? 'var(--risk-high)' : 'inherit' }}>
                  {selectedEntity.feature_summary?.failed_login_count ?? 0} ({(selectedEntity.feature_summary?.failed_login_ratio * 100 || 0).toFixed(0)}%)
                </div>
              </div>
              <div className="feature-cell">
                <div className="label">Off-Hours Events</div>
                <div className="val">{selectedEntity.feature_summary?.odd_hour_count ?? 0}</div>
              </div>
              <div className="feature-cell">
                <div className="label">Privilege Change Events</div>
                <div className="val" style={{ color: (selectedEntity.feature_summary?.privilege_change_count || 0) > 0 ? 'var(--risk-critical)' : 'inherit' }}>
                  {selectedEntity.feature_summary?.privilege_change_count ?? 0}
                </div>
              </div>
              <div className="feature-cell">
                <div className="label">Firewall Denied Packets</div>
                <div className="val">{selectedEntity.feature_summary?.firewall_denied_count ?? 0}</div>
              </div>
              <div className="feature-cell">
                <div className="label">Total Data Transferred</div>
                <div className="val">{selectedEntity.feature_summary?.total_bytes_mb ?? 0} MB</div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
