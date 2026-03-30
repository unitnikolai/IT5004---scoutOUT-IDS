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
  sourceIP: '192.168.1.105',
  destIP: '192.168.1.1',
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

const Threats: React.FC = () => {
  // Automatically cancel requests when navigating away
  useRouteCleanup();

  const [threats, setThreats] = useState<Threat[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedThreat, setSelectedThreat] = useState<Threat | null>(null);
  const [filterSeverity, setFilterSeverity] = useState('all');
  const [abortController, setAbortController] = useState(new AbortController());

  const fetchThreats = async (hasCachedData: boolean = false) => {
    try {
      // Only show loading if we have no cached data
      if (!hasCachedData) {
        setLoading(true);
      }
      setError(null);
      const response = await fetch(`${API_BASE_URL}/threats/enhanced`, {
        signal: abortController.signal
      });
      if (!response.ok) throw new Error('Failed to fetch threats');
      const data = await response.json();
      const fetchedThreats = data.threats || [];
      
      if (fetchedThreats.length > 0) {
        // Replace cache with fresh threats
        threatsCache.replace(fetchedThreats);
        setThreats(fetchedThreats);
      } else {
        // No threats detected - show example threat with cached threats
        const cached = threatsCache.load();
        if (cached.length === 0) {
          // No real threats and no cache - show example
          setThreats([EXAMPLE_THREAT]);
          console.log('[Threats] No real threats detected, showing example');
        } else {
          // Show cached threats
          setThreats(cached);
        }
      }
    } catch (err: any) {
      // Silently ignore abort errors (user navigated away or request was cancelled)
      // Includes DNS cancellations (ns binding) that occur during navigation
      const message = err?.message?.toLowerCase() || '';
      const isAbortError = (
        err?.name === 'AbortError' || 
        message.includes('abort') ||
        message.includes('ns binding') ||
        message.includes('cancel')
      );
      if (!isAbortError) {
        console.error('Error fetching threats:', err);
        setError('Failed to load threats');
      }
      // IMPORTANT: Keep existing data if available - do not wipe state on abort errors
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    // Load cached data on mount
    const cached = threatsCache.load();
    const hasCachedData = cached.length > 0;
    
    if (hasCachedData) {
      setThreats(cached);
      console.log('[Threats] Loaded from cache:', cached.length, 'threats');
    }

    // Fetch fresh threats (skip loading indicator if we have cached data)
    fetchThreats(hasCachedData);
    
    // Refresh every 10 seconds
    const interval = setInterval(() => {
      fetchThreats(true); // Always skip loading for polling since we keep cached data
    }, 10000);
    
    // Cleanup: cancel pending requests when component unmounts
    return () => {
      clearInterval(interval);
      abortController.abort();
    };
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
    ? threats 
    : threats.filter(t => t.severity === filterSeverity);

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
          {loading ? 'Loading...' : `${filteredThreats.length} threat(s) detected`}
          <button
            className="cache-clear-btn"
            onClick={async () => {
              threatsCache.clear();
              setThreats([EXAMPLE_THREAT]); // Show example when cleared
              console.log('[Threats] Cache cleared, showing example threat...');
              // Immediately fetch fresh data after clearing
              await fetchThreats();
            }}
            title="Clear threats cache"
          >
            Clear Cache
          </button>
        </div>
      </div>

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
        {filteredThreats.map(threat => (
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
        ))}
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
