import React, { useState, useEffect } from 'react';
import { FiAlertTriangle } from 'react-icons/fi';
import './Threats.css';

const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://172.20.0.31:5050/api';

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
  const [threats, setThreats] = useState<Threat[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedThreat, setSelectedThreat] = useState<Threat | null>(null);
  const [filterSeverity, setFilterSeverity] = useState('all');

  useEffect(() => {
    const fetchThreats = async () => {
      try {
        setLoading(true);
        setError(null);
        const response = await fetch(`${API_BASE_URL}/threats/enhanced`);
        if (!response.ok) throw new Error('Failed to fetch threats');
        const data = await response.json();
        setThreats(data.threats || []);
      } catch (err) {
        console.error('Error fetching threats:', err);
        setError('Failed to load threats');
      } finally {
        setLoading(false);
      }
    };

    fetchThreats();
    
    // Refresh every 10 seconds
    const interval = setInterval(fetchThreats, 10000);
    return () => clearInterval(interval);
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
