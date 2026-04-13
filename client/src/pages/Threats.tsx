import React, { useState, useEffect } from 'react';
import { useRouteCleanup } from '../hooks/useRouteCleanup';
import { FiAlertTriangle } from 'react-icons/fi';
import threatsCache from '../services/threatsCache';
import './Threats.css';

const getApiUrl = (): string => {
  // Use environment variable if set (Docker production)
  if (process.env.REACT_APP_API_URL) {
    return process.env.REACT_APP_API_URL;
  }
  
  // Otherwise, dynamically detect based on frontend URL
  const protocol = window.location.protocol; // http: or https:
  const hostname = window.location.hostname; // localhost, 192.168.x.x, etc.
  const port = ':5050'; // Backend API port
  const path = '/api';
  
  return `${protocol}//${hostname}${port}${path}`;
};

const API_BASE_URL = getApiUrl();

// Default example threat for when no threats are detected
const EXAMPLE_THREAT: Threat = {
  id: 9999,
  message: 'Suspicious Port Scan Detected (Example)',
  details: 'Multiple connection attempts detected on port 22 (SSH) from unknown source',
  sourceIP: '192.168.4.105',
  destIP: '192.168.4.1',
  severity: 'medium',
  timestamp: new Date().toISOString(),
  type: 'port-scan'
};

interface Threat {
  id: number;
  message: string;
  details: string;
  sourceIP: string;
  destIP: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  timestamp: string;
  type?: string;
}

interface VirusTotalThreat extends Threat {
  type: 'virustotal-https' | 'virustotal-port-scan';
  vtReport?: {
    malicious: number;
    suspicious: number;
    undetected: number;
  };
}

interface IPReputation {
  ip: string;
  malicious: number;
  suspicious: number;
  undetected: number;
  isSafe: boolean;
  severity: 'critical' | 'high' | 'medium' | 'low';
}

const Threats: React.FC = () => {
  useRouteCleanup();

  const [allThreats, setAllThreats] = useState<Threat[]>([]);
  const [ipReputation, setIpReputation] = useState<IPReputation[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedThreat, setSelectedThreat] = useState<Threat | null>(null);
  const [filterSeverity, setFilterSeverity] = useState('all');
  const abortRef = React.useRef<AbortController | null>(null);

  const fetchThreats = async () => {
    // Cancel any in-flight request
    if (abortRef.current) abortRef.current.abort();
    abortRef.current = new AbortController();

    try {
      setError(null);
      const response = await fetch(`${API_BASE_URL}/threats/enhanced`, {
        signal: abortRef.current.signal
      });
      if (!response.ok) throw new Error(`Server returned ${response.status}`);
      const data = await response.json();
      const fetched: Threat[] = data.threats || [];

      // Build IP reputation map from VT threats
      const ipReputationMap = new Map<string, IPReputation>();
      fetched.forEach((t: any) => {
        if ((t.type === 'virustotal-https' || t.type === 'virustotal-port-scan') && t.vtReport) {
          const ip = t.sourceIP;
          if (!ipReputationMap.has(ip)) {
            const { malicious, suspicious, undetected } = t.vtReport;
            ipReputationMap.set(ip, {
              ip,
              malicious,
              suspicious,
              undetected,
              isSafe: malicious === 0 && suspicious === 0,
              severity: malicious > 0 ? 'critical' : suspicious > 0 ? 'high' : 'low'
            });
          }
        }
      });

      threatsCache.replace(fetched);
      setAllThreats(fetched.length > 0 ? fetched : [EXAMPLE_THREAT]);
      setIpReputation(Array.from(ipReputationMap.values()));
    } catch (err: any) {
      if (err?.name === 'AbortError') return; // navigated away — keep existing data
      console.error('Error fetching threats:', err);
      // Fall back to cache so the page never stays blank
      const cached = threatsCache.load();
      setAllThreats(cached.length > 0 ? cached : [EXAMPLE_THREAT]);
      setError('Could not reach server — showing cached data');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    // Show cached data immediately so the page isn't blank while fetching
    const cached = threatsCache.load();
    if (cached.length > 0) {
      setAllThreats(cached);
      setLoading(false);
    }

    fetchThreats();
    const interval = setInterval(fetchThreats, 30000);

    return () => {
      clearInterval(interval);
      abortRef.current?.abort();
    };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const getSeverityColor = (severity: string) => {
    const colors = {
      low: '#4CAF50',
      medium: '#FF9800',
      high: '#FF5722',
      critical: '#D32F2F'
    };
    return colors[severity as keyof typeof colors] || '#666';
  };

  const formatTimestamp = (timestamp: string) => {
    return new Date(timestamp).toLocaleString();
  };

  const filteredThreats = filterSeverity === 'all'
    ? allThreats
    : allThreats.filter(t => t.severity === filterSeverity);

  return (
    <div className="threats-page">
      <div className="page-header">
        <h1>Threats</h1>
        <p className="subtitle">Security Threat Analysis</p>
      </div>

      {error && <div className="error-banner">{error}</div>}

      <div className="threats-controls">
        <div className="filter-group">
          <label>Filter by Severity:</label>
          <select value={filterSeverity} onChange={(e) => setFilterSeverity(e.target.value)}>
            <option value="all">All Severity Levels</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </div>
        <div className="threat-count">
          {loading ? 'Scanning…' : `${filteredThreats.length} threat(s) detected`}
          <button
            className="cache-clear-btn"
            onClick={() => {
              threatsCache.clear();
              setAllThreats([]);
              setIpReputation([]);
              setLoading(true);
              fetchThreats();
            }}
            title="Clear cache and refresh"
          >
            Refresh
          </button>
        </div>
      </div>

      {/* Threats List — all threats (including VirusTotal) use the same card */}
      {loading ? (
        <div className="loading-state">
          <p>Loading threats...</p>
        </div>
      ) : filteredThreats.length === 0 ? (
        <div className="empty-state">
          <p>No threats detected. Network appears secure.</p>
        </div>
      ) : (
      <div className="threats-list">
        {filteredThreats.map(threat => {
          const vt = (threat as any).vtReport;
          return (
          <div 
            key={threat.id} 
            className="threat-card"
            onClick={() => setSelectedThreat(threat)}
          >
            <div className="threat-header">
              <div className="threat-icon" style={{ color: getSeverityColor(threat.severity) }}>
                <FiAlertTriangle size={24} />
              </div>
              <div className="threat-severity" style={{ backgroundColor: getSeverityColor(threat.severity) }}>
                {threat.severity}
              </div>
            </div>

            <div className="threat-body">
              <h3>{threat.message}</h3>
              <div className="threat-meta">
                <span className="threat-ip">From: {threat.sourceIP}</span>
                <span className="threat-type">{threat.type || 'packet-analysis'}</span>
              </div>
              <div className="threat-stats">
                <div className="stat-item">
                  <span className="stat-label">To IP:</span>
                  <span className="stat-value">{threat.destIP}</span>
                </div>
                <div className="stat-item">
                  <span className="stat-label">Detected:</span>
                  <span className="stat-value">{formatTimestamp(threat.timestamp)}</span>
                </div>
                {vt && (
                  <>
                    <div className="stat-item">
                      <span className="stat-label">VT Malicious:</span>
                      <span className="stat-value" style={{ color: '#D32F2F', fontWeight: 600 }}>{vt.malicious}</span>
                    </div>
                    <div className="stat-item">
                      <span className="stat-label">VT Suspicious:</span>
                      <span className="stat-value" style={{ color: '#FF9800', fontWeight: 600 }}>{vt.suspicious}</span>
                    </div>
                  </>
                )}
              </div>
              <div className="threat-details">
                <p>{threat.details}</p>
              </div>
            </div>

            <div className="threat-actions">
              <button className="action-btn block-btn">Block IP</button>
              <button className="action-btn investigate-btn">Investigate</button>
            </div>
          </div>
          );
        })}
      </div>
      )}

      {/* Threat Detail Modal */}
      {selectedThreat && (
        <div className="modal-overlay" onClick={() => setSelectedThreat(null)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h2>Threat Details</h2>
              <button className="close-button" onClick={() => setSelectedThreat(null)}>×</button>
            </div>
            <div className="modal-body">
              <div className="detail-section">
                <h3>Threat Information</h3>
                <div className="detail-grid">
                  <div className="detail-row">
                    <strong>Message:</strong>
                    <span>{selectedThreat.message}</span>
                  </div>
                  <div className="detail-row">
                    <strong>Source IP:</strong>
                    <span>{selectedThreat.sourceIP}</span>
                  </div>
                  <div className="detail-row">
                    <strong>Destination IP:</strong>
                    <span>{selectedThreat.destIP}</span>
                  </div>
                  <div className="detail-row">
                    <strong>Type:</strong>
                    <span>{selectedThreat.type || 'packet-analysis'}</span>
                  </div>
                  <div className="detail-row">
                    <strong>Severity:</strong>
                    <span style={{ color: getSeverityColor(selectedThreat.severity), fontWeight: 'bold' }}>
                      {selectedThreat.severity.toUpperCase()}
                    </span>
                  </div>
                </div>
              </div>

              <div className="detail-section">
                <h3>Detection Details</h3>
                <div className="detail-grid">
                  <div className="detail-row">
                    <strong>Detected At:</strong>
                    <span>{formatTimestamp(selectedThreat.timestamp)}</span>
                  </div>
                  <div className="detail-row">
                    <strong>Details:</strong>
                    <span>{selectedThreat.details}</span>
                  </div>
                </div>
              </div>

              <div className="modal-actions">
                <button className="modal-action-btn block">Block IP</button>
                <button className="modal-action-btn investigate">Investigate</button>
                <button className="modal-action-btn dismiss">Dismiss</button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default Threats;
