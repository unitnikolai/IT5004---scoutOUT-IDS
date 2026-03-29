import React, { useState, useEffect } from 'react';
import { FiActivity, FiAlertTriangle, FiUsers, FiFilter, FiRefreshCw } from 'react-icons/fi';
import { LineChart, Line, ResponsiveContainer, Tooltip } from 'recharts';
import dashboardService, { DashboardStats, Alert, NewDevice, Threat, ThreatActivity } from '../services/dashboardService';
import dashboardCache from '../services/dashboardCache';
import './Dashboard.css';

const Dashboard: React.FC = () => {
  const [stats, setStats] = useState<DashboardStats>({
    totalDevices: 0,
    packetsScanned: 0,
    threatsBlocked: 0,
    parentalBlocks: 0,
    networkHealth: 0
  });

  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [newDevices, setNewDevices] = useState<NewDevice[]>([]);
  const [topThreats, setTopThreats] = useState<Threat[]>([]);
  const [threatActivity, setThreatActivity] = useState<ThreatActivity[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);

  const fetchDashboardData = async () => {
    try {
      setLoading(true);
      setError(null);

      const data = await dashboardService.getAllData();
      console.log('Dashboard data:', data);
      
      // Update state
      setStats(data.stats);
      setAlerts(data.alerts);
      setNewDevices(data.devices);
      setTopThreats(data.threats);
      setThreatActivity(data.activity);
      setLastUpdated(new Date());
      
      // Save to persistent cache
      dashboardCache.save({
        stats: data.stats,
        alerts: data.alerts,
        devices: data.devices,
        threats: data.threats,
        activity: data.activity
      });
    } catch (err: any) {
      // Silently ignore abort errors (user navigated away, DNS cancelled, or request was cancelled)
      const message = err?.message?.toLowerCase() || '';
      const isAbortError = (
        err?.name === 'AbortError' ||
        err?.code === 'ECONNABORTED' ||
        err?.code === 'ERR_CANCELED' ||
        message.includes('abort') ||
        message.includes('cancel') ||
        message.includes('ns binding')
      );
      if (!isAbortError) {
        console.error('Failed to fetch dashboard data:', err);
        setError('Failed to load dashboard data. Please try again.');
      }
      // IMPORTANT: Keep existing data on abort - never wipe state
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    // Load cached data on mount
    const cached = dashboardCache.load();
    if (cached) {
      setStats(cached.stats);
      setAlerts(cached.alerts);
      setNewDevices(cached.devices);
      setTopThreats(cached.threats);
      setThreatActivity(cached.activity);
      console.log('[Dashboard] Loaded from cache');
    }
    
    // Fetch fresh data
    fetchDashboardData();
    // Auto-refresh every 5 seconds - with 2s cache on backend, reduces actual computation
    const interval = setInterval(fetchDashboardData, 5000);
    
    // Cleanup: cancel pending requests and clear interval when component unmounts
    return () => {
      clearInterval(interval);
      dashboardService.cancelRequests(); // Cancel any pending API calls
    };
  }, []);

  const formatTimestamp = (timestamp: string) => {
    const date = new Date(timestamp);
    return date.toLocaleString();
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

  const getSeverityColor = (severity: string) => {
    const colors = {
      low: '#4CAF50',
      medium: '#FF9800',
      high: '#FF5722',
      critical: '#D32F2F'
    };
    return colors[severity as keyof typeof colors] || '#666';
  };

  const getHealthColor = (health: number) => {
    if (health >= 80) return '#4CAF50';
    if (health >= 60) return '#FF9800';
    return '#FF5722';
  };

  return (
    <div className="dashboard-page">
      <div className="page-header">
        <h1>Dashboard</h1>
        <p className="subtitle">
          Network Security Overview
          {lastUpdated && (
            <span className="last-updated">
              • Last updated: {lastUpdated.toLocaleTimeString()}
            </span>
          )}
        </p>
      </div>

      {error && (
        <div className="error-banner">
          <p>{error}</p>
          <button onClick={fetchDashboardData} disabled={loading}>
            Try Again
          </button>
        </div>
      )}

      {/* Refresh Button */}
      <div className="dashboard-controls">
        <button 
          className="refresh-btn" 
          onClick={fetchDashboardData} 
          disabled={loading}
        >
          <FiRefreshCw className={loading ? 'spinning' : ''} /> 
          {loading ? 'Loading...' : 'Refresh Data'}
        </button>
        <button
          className="cache-clear-btn"
          onClick={async () => {
            dashboardCache.clear();
            setStats({ totalDevices: 0, packetsScanned: 0, threatsBlocked: 0, parentalBlocks: 0, networkHealth: 0 });
            setAlerts([]);
            setNewDevices([]);
            setTopThreats([]);
            setThreatActivity([]);
            console.log('[Dashboard] Cache cleared, fetching fresh data...');
            // Immediately fetch fresh data after clearing
            await fetchDashboardData();
          }}
          title="Clear dashboard cache"
        >
          Clear Cache
        </button>
      </div>

      {/* Quick Stats Cards */}
      <div className="stats-grid">
        <div className="stat-card">
          <div className="stat-icon" style={{ backgroundColor: '#E3F2FD' }}>
            <FiUsers color="#2196F3" size={24} />
          </div>
          <div className="stat-content">
            <div className="stat-value">{stats.totalDevices}</div>
            <div className="stat-label">Total Devices</div>
          </div>
        </div>

        <div className="stat-card">
          <div className="stat-icon" style={{ backgroundColor: '#F3E5F5' }}>
            <FiActivity color="#9C27B0" size={24} />
          </div>
          <div className="stat-content">
            <div className="stat-value">{stats.packetsScanned.toLocaleString()}</div>
            <div className="stat-label">Packets Scanned Today</div>
          </div>
        </div>

        <div className="stat-card">
          <div className="stat-icon" style={{ backgroundColor: '#FFEBEE' }}>
            <FiAlertTriangle color="#F44336" size={24} />
          </div>
          <div className="stat-content">
            <div className="stat-value">{stats.threatsBlocked}</div>
            <div className="stat-label">Threats Blocked</div>
          </div>
        </div>

        <div className="stat-card">
          <div className="stat-icon" style={{ backgroundColor: '#FFF3E0' }}>
            <FiFilter color="#FF9800" size={24} />
          </div>
          <div className="stat-content">
            <div className="stat-value">{stats.parentalBlocks}</div>
            <div className="stat-label">Parental Control Blocks</div>
          </div>
        </div>
      </div>

      <div className="dashboard-grid">
        {/* Network Health Gauge */}
        <div className="dashboard-card network-health-card">
          <h3>Network Health</h3>
          <div className="health-gauge-container">
            <div className="health-gauge">
              <div 
                className="health-circle"
                style={{ borderColor: getHealthColor(stats.networkHealth) }}
              >
                <div className="health-value">{stats.networkHealth}%</div>
                <div className="health-label">Healthy</div>
              </div>
              <div className="pulse-ring" style={{ borderColor: getHealthColor(stats.networkHealth) }}></div>
            </div>
          </div>
        </div>

        {/* Threat Activity Sparkline */}
        <div className="dashboard-card threat-activity-card">
          <h3>Threat Activity (24h)</h3>
          <ResponsiveContainer width="100%" height={150}>
            <LineChart data={threatActivity}>
              <Line 
                type="monotone" 
                dataKey="threats" 
                stroke="#F44336" 
                strokeWidth={2}
                dot={false}
              />
              <Tooltip />
            </LineChart>
          </ResponsiveContainer>
        </div>

        {/* New Devices Widget */}
        <div className="dashboard-card new-devices-card">
          <h3>New Devices</h3>
          <div className="devices-list">
            {newDevices.map(device => (
              <div key={device.id} className="device-item">
                <div className="device-info">
                  <div className="device-name">{device.name}</div>
                  <div className="device-details">{device.ip} • {device.type}</div>
                </div>
                <div className="device-time">{formatRelativeTime(device.joinedAt)}</div>
              </div>
            ))}
          </div>
        </div>

        {/* Top Threats Banner */}
        <div className="dashboard-card top-threats-card">
          <h3>Top Threats</h3>
          <div className="threats-list">
            {topThreats.map(threat => (
              <div key={threat.id} className="threat-item">
                <div className="threat-info">
                  <div className="threat-domain">{threat.domain}</div>
                  <div className="threat-ip">{threat.ip}</div>
                </div>
                <div className="threat-meta">
                  <span 
                    className="threat-severity-badge"
                    style={{ backgroundColor: getSeverityColor(threat.severity) }}
                  >
                    {threat.severity}
                  </span>
                  <span className="threat-count">{threat.count} blocks</span>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Recent Alerts Timeline */}
        <div className="dashboard-card alerts-card">
          <h3>Recent Alerts</h3>
          <div className="alerts-timeline">
            {alerts.map(alert => (
              <div key={alert.id} className="alert-item">
                <div 
                  className="alert-indicator"
                  style={{ backgroundColor: getSeverityColor(alert.severity) }}
                ></div>
                <div className="alert-content">
                  <div className="alert-message">{alert.message}</div>
                  <div className="alert-timestamp">{formatTimestamp(alert.timestamp)}</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;
