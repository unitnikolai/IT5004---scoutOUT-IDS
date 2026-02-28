import React, { useState } from 'react';
import { FiAlertTriangle } from 'react-icons/fi';
import './Threats.css';

interface Threat {
  id: number;
  domain: string;
  ip: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  category: string;
  count: number;
  lastSeen: string;
  devices: string[];
  virusTotalScore: number;
}

const Threats: React.FC = () => {
  const [threats] = useState<Threat[]>([
    {
      id: 1,
      domain: 'malware.example.com',
      ip: '45.33.32.156',
      severity: 'critical',
      category: 'Malware',
      count: 15,
      lastSeen: new Date().toISOString(),
      devices: ['Gaming-PC', 'iPhone-12'],
      virusTotalScore: 85
    },
    {
      id: 2,
      domain: 'phishing-site.net',
      ip: '104.28.12.34',
      severity: 'high',
      category: 'Phishing',
      count: 8,
      lastSeen: new Date(Date.now() - 3600000).toISOString(),
      devices: ['Laptop'],
      virusTotalScore: 72
    },
    {
      id: 3,
      domain: 'suspicious-ads.com',
      ip: '172.67.133.45',
      severity: 'medium',
      category: 'Command & Control',
      count: 5,
      lastSeen: new Date(Date.now() - 7200000).toISOString(),
      devices: ['Smart-TV'],
      virusTotalScore: 45
    },
    {
      id: 4,
      domain: 'botnet-server.org',
      ip: '185.220.101.12',
      severity: 'high',
      category: 'Botnet',
      count: 12,
      lastSeen: new Date(Date.now() - 10800000).toISOString(),
      devices: ['IoT-Camera'],
      virusTotalScore: 78
    }
  ]);

  const [selectedThreat, setSelectedThreat] = useState<Threat | null>(null);
  const [filterCategory, setFilterCategory] = useState('all');

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

  const getScoreColor = (score: number) => {
    if (score >= 70) return '#D32F2F';
    if (score >= 40) return '#FF9800';
    return '#4CAF50';
  };

  const filteredThreats = filterCategory === 'all' 
    ? threats 
    : threats.filter(t => t.category === filterCategory);

  return (
    <div className="threats-page">
      <div className="page-header">
        <h1>Threats</h1>
        <p className="subtitle">Security Threat Analysis</p>
      </div>

      <div className="threats-controls">
        <div className="filter-group">
          <label>Filter by Category:</label>
          <select value={filterCategory} onChange={(e) => setFilterCategory(e.target.value)}>
            <option value="all">All Categories</option>
            <option value="Malware">Malware</option>
            <option value="Phishing">Phishing</option>
            <option value="Botnet">Botnet</option>
            <option value="Command & Control">Command & Control</option>
          </select>
        </div>
      </div>

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
              <h3>{threat.domain}</h3>
              <div className="threat-meta">
                <span className="threat-ip">{threat.ip}</span>
                <span className="threat-category">{threat.category}</span>
              </div>
              <div className="threat-stats">
                <div className="stat-item">
                  <span className="stat-label">Blocked Count:</span>
                  <span className="stat-value">{threat.count}</span>
                </div>
                <div className="stat-item">
                  <span className="stat-label">Last Seen:</span>
                  <span className="stat-value">{formatTimestamp(threat.lastSeen)}</span>
                </div>
                <div className="stat-item">
                  <span className="stat-label">Affected Devices:</span>
                  <span className="stat-value">{threat.devices.join(', ')}</span>
                </div>
              </div>
              <div className="virustotal-score">
                <span>VirusTotal Score:</span>
                <div className="score-bar">
                  <div 
                    className="score-fill" 
                    style={{ 
                      width: `${threat.virusTotalScore}%`,
                      backgroundColor: getScoreColor(threat.virusTotalScore)
                    }}
                  ></div>
                </div>
                <span className="score-value">{threat.virusTotalScore}/100</span>
              </div>
            </div>

            <div className="threat-actions">
              <button className="action-btn block-btn">Block Permanently</button>
              <button className="action-btn quarantine-btn">Quarantine Device</button>
            </div>
          </div>
        ))}
      </div>

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
                    <strong>Domain:</strong>
                    <span>{selectedThreat.domain}</span>
                  </div>
                  <div className="detail-row">
                    <strong>IP Address:</strong>
                    <span>{selectedThreat.ip}</span>
                  </div>
                  <div className="detail-row">
                    <strong>Category:</strong>
                    <span>{selectedThreat.category}</span>
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
                <h3>Activity</h3>
                <div className="detail-grid">
                  <div className="detail-row">
                    <strong>Total Blocks:</strong>
                    <span>{selectedThreat.count}</span>
                  </div>
                  <div className="detail-row">
                    <strong>Last Detected:</strong>
                    <span>{formatTimestamp(selectedThreat.lastSeen)}</span>
                  </div>
                  <div className="detail-row">
                    <strong>Affected Devices:</strong>
                    <span>{selectedThreat.devices.join(', ')}</span>
                  </div>
                </div>
              </div>

              <div className="detail-section">
                <h3>VirusTotal Analysis</h3>
                <div className="virustotal-details">
                  <div className="vt-score" style={{ color: getScoreColor(selectedThreat.virusTotalScore) }}>
                    <strong>Threat Score:</strong>
                    <span>{selectedThreat.virusTotalScore}/100</span>
                  </div>
                  <p className="vt-description">
                    This threat has been identified by multiple security vendors. 
                    The score indicates a {selectedThreat.virusTotalScore >= 70 ? 'high' : 'moderate'} risk level.
                  </p>
                </div>
              </div>

              <div className="modal-actions">
                <button className="modal-action-btn block">Block Domain</button>
                <button className="modal-action-btn quarantine">Quarantine Devices</button>
                <button className="modal-action-btn report">Report False Positive</button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default Threats;
