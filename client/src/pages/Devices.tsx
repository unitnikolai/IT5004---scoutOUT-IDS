import React, { useState, useEffect } from 'react';
import { FiSmartphone, FiMonitor, FiWifi, FiCoffee } from 'react-icons/fi';
import './Devices.css';

const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://172.20.0.31:5050/api';

interface Device {
  id: number;
  name: string;
  ip: string;
  mac: string;
  vendor: string;
  type: string;
  firstSeen: string;
  lastSeen: string;
  trust: 'trusted' | 'untrusted' | 'blocked';
  assignedTo: string;
  bandwidth: number;
}

const Devices: React.FC = () => {
  const [devices, setDevices] = useState<Device[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedDevice, setSelectedDevice] = useState<Device | null>(null);

  useEffect(() => {
    const fetchDevices = async () => {
      try {
        setLoading(true);
        setError(null);
        const response = await fetch(`${API_BASE_URL}/devices/all`);
        if (!response.ok) throw new Error('Failed to fetch devices');
        const data = await response.json();
        setDevices(data.devices || []);
      } catch (err) {
        console.error('Error fetching devices:', err);
        setError('Failed to load devices');
      } finally {
        setLoading(false);
      }
    };

    fetchDevices();
    
    // Refresh every 10 seconds
    const interval = setInterval(fetchDevices, 10000);
    return () => clearInterval(interval);
  }, []);

  const getDeviceIcon = (type: string) => {
    switch (type.toLowerCase()) {
      case 'mobile': return <FiSmartphone size={24} />;
      case 'computer': return <FiMonitor size={24} />;
      case 'iot': return <FiWifi size={24} />;
      default: return <FiCoffee size={24} />;
    }
  };

  const getTrustColor = (trust: string) => {
    switch (trust) {
      case 'trusted': return '#4CAF50';
      case 'untrusted': return '#FF9800';
      case 'blocked': return '#F44336';
      default: return '#999';
    }
  };

  const formatTimestamp = (timestamp: string) => {
    return new Date(timestamp).toLocaleString();
  };

  const formatRelativeTime = (timestamp: string) => {
    const date = new Date(timestamp);
    const now = new Date();
    const diffMs = now.getTime() - date.getTime();
    const diffMins = Math.floor(diffMs / 60000);
    
    if (diffMins < 60) return `${diffMins}m ago`;
    const diffHours = Math.floor(diffMins / 60);
    if (diffHours < 24) return `${diffHours}h ago`;
    const diffDays = Math.floor(diffHours / 24);
    return `${diffDays}d ago`;
  };

  return (
    <div className="devices-page">
      <div className="page-header">
        <h1>Devices</h1>
        <p className="subtitle">Network Device Inventory</p>
      </div>

      {error && <div className="error-banner">{error}</div>}

      {loading ? (
        <div className="loading-state">
          <p>Loading devices...</p>
        </div>
      ) : devices.length === 0 ? (
        <div className="empty-state">
          <p>No devices detected on network.</p>
        </div>
      ) : (
      <div className="devices-grid">
        {devices.map(device => (
          <div 
            key={device.id} 
            className="device-card"
            onClick={() => setSelectedDevice(device)}
          >
            <div className="device-header">
              <div className="device-icon" style={{ color: getTrustColor(device.trust) }}>
                {getDeviceIcon(device.type)}
              </div>
              <div className="device-trust-badge" style={{ backgroundColor: getTrustColor(device.trust) }}>
                {device.trust}
              </div>
            </div>
            
            <div className="device-body">
              <h3>{device.name}</h3>
              <div className="device-info-grid">
                <div className="info-item">
                  <span className="label">IP Address:</span>
                  <span className="value">{device.ip}</span>
                </div>
                <div className="info-item">
                  <span className="label">MAC:</span>
                  <span className="value">{device.mac}</span>
                </div>
                <div className="info-item">
                  <span className="label">Vendor:</span>
                  <span className="value">{device.vendor}</span>
                </div>
                <div className="info-item">
                  <span className="label">Type:</span>
                  <span className="value">{device.type}</span>
                </div>
                <div className="info-item">
                  <span className="label">Last Seen:</span>
                  <span className="value">{formatRelativeTime(device.lastSeen)}</span>
                </div>
                <div className="info-item">
                  <span className="label">Assigned To:</span>
                  <span className="value">{device.assignedTo}</span>
                </div>
              </div>
              
              <div className="device-bandwidth">
                <span className="bandwidth-label">Bandwidth Usage:</span>
                <div className="bandwidth-bar">
                  <div 
                    className="bandwidth-fill" 
                    style={{ width: `${Math.min(device.bandwidth / 10, 100)}%` }}
                  ></div>
                </div>
                <span className="bandwidth-value">{device.bandwidth} Mbps</span>
              </div>
            </div>
          </div>
        ))}
      </div>
      )}

      {/* Device Detail Modal */}
      {selectedDevice && (
        <div className="modal-overlay" onClick={() => setSelectedDevice(null)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h2>Device Details: {selectedDevice.name}</h2>
              <button className="close-button" onClick={() => setSelectedDevice(null)}>×</button>
            </div>
            <div className="modal-body">
              <div className="detail-section">
                <h3>Network Information</h3>
                <div className="detail-grid">
                  <div className="detail-item">
                    <strong>IP Address:</strong>
                    <span>{selectedDevice.ip}</span>
                  </div>
                  <div className="detail-item">
                    <strong>MAC Address:</strong>
                    <span>{selectedDevice.mac}</span>
                  </div>
                  <div className="detail-item">
                    <strong>Vendor:</strong>
                    <span>{selectedDevice.vendor}</span>
                  </div>
                </div>
              </div>

              <div className="detail-section">
                <h3>Activity</h3>
                <div className="detail-grid">
                  <div className="detail-item">
                    <strong>First Seen:</strong>
                    <span>{formatTimestamp(selectedDevice.firstSeen)}</span>
                  </div>
                  <div className="detail-item">
                    <strong>Last Seen:</strong>
                    <span>{formatTimestamp(selectedDevice.lastSeen)}</span>
                  </div>
                  <div className="detail-item">
                    <strong>Bandwidth:</strong>
                    <span>{selectedDevice.bandwidth} Mbps</span>
                  </div>
                </div>
              </div>

              <div className="detail-section">
                <h3>Trust & Assignment</h3>
                <div className="detail-actions">
                  <select value={selectedDevice.trust} className="trust-select">
                    <option value="trusted">Trusted</option>
                    <option value="untrusted">Untrusted</option>
                    <option value="blocked">Blocked</option>
                  </select>
                  <select value={selectedDevice.assignedTo} className="assign-select">
                    <option value="Parent">Parent</option>
                    <option value="Child">Child</option>
                    <option value="Guest">Guest</option>
                  </select>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default Devices;
