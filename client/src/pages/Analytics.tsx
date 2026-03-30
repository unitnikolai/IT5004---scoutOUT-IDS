import React, { useState, useEffect } from 'react';
import { FiDownload, FiTrendingUp, FiRefreshCw } from 'react-icons/fi';
import { useRouteCleanup } from '../hooks/useRouteCleanup';
import { LineChart, Line, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts';
import analyticsService, { LogEntry, TimeSeriesData, TopDevice } from '../services/analyticsService';
import './Analytics.css';

// Example logs for when no activity has been detected
const EXAMPLE_LOGS: LogEntry[] = [
  {
    id: 9999,
    timestamp: new Date().toISOString(),
    type: 'device',
    message: 'New Device Detected (Example)',
    details: 'Device 192.168.1.50 connected to network'
  },
  {
    id: 9998,
    timestamp: new Date(Date.now() - 3600000).toISOString(),
    type: 'threat',
    message: 'Suspicious Port Scan Detected (Example)',
    details: 'Multiple connection attempts detected on port 22 from unknown source'
  },
  {
    id: 9997,
    timestamp: new Date(Date.now() - 7200000).toISOString(),
    type: 'parental',
    message: 'Restricted Content Blocked (Example)',
    details: 'Content from domain example-adult-site.com was blocked per parental controls'
  }
];

const Analytics: React.FC = () => {
  // Automatically cancel requests when navigating away
  useRouteCleanup();

  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [threatsPerDay, setThreatsPerDay] = useState<TimeSeriesData[]>([]);
  const [deviceActivity, setDeviceActivity] = useState<TimeSeriesData[]>([]);
  const [mostActiveDevices, setMostActiveDevices] = useState<TopDevice[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);

  const fetchAnalyticsData = async (hasCachedData: boolean = false) => {
    try {
      setLoading(true);
      setError(null);

      const [logsResponse, threatsResponse, devicesResponse, topDevicesResponse] = await Promise.all([
        analyticsService.getLogs(),
        analyticsService.getThreatsTimeline(),
        analyticsService.getDeviceActivity(),
        analyticsService.getTopDevices()
      ]);

      const logsData = logsResponse.logs || [];
      const threatsData = threatsResponse.data || [];
      const devicesData = devicesResponse.data || [];
      const topDevicesData = topDevicesResponse.data || [];

      setLogs(logsData);
      setThreatsPerDay(threatsData);
      setDeviceActivity(devicesData);
      setMostActiveDevices(topDevicesData);
      setLastUpdated(new Date());
      
      console.log(`[Analytics] Fetched from backend storage: ${logsData.length} logs, ${threatsData.length} threat days, ${devicesData.length} device days, ${topDevicesData.length} top devices`);
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
        console.error('Failed to fetch analytics data:', err);
        setError('Failed to load analytics data from backend. Please try again.');
      }
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    // Always fetch fresh analytics data from backend storage
    // Backend now always pulls from storage - this is the source of truth
    
    // Fetch fresh data immediately
    fetchAnalyticsData(false);
    
    // Poll for updated analytics every 1 minute
    const interval = setInterval(() => {
      fetchAnalyticsData(false);
    }, 60000); // 1 minute
    
    // Cleanup: cancel pending requests and clear interval when component unmounts
    return () => {
      clearInterval(interval);
      analyticsService.cancelRequests?.();
    };
  }, []);

  const exportLogs = async (format: 'csv') => {
    try {
      analyticsService.exportLogsToCSV(logs);
    } catch (error) {
      console.error('Error exporting logs:', error);
      setError(`Failed to export as ${format.toUpperCase()}`);
    }
  };

  const formatTimestamp = (timestamp: string) => {
    return new Date(timestamp).toLocaleString();
  };

  const getTypeColor = (type: string) => {
    const colors = {
      threat: '#F44336',
      device: '#2196F3',
      parental: '#FF9800'
    };
    return colors[type as keyof typeof colors] || '#666';
  };

  return (
    <div className="analytics-page">
      <div className="page-header">
        <h1>Analytics</h1>
        <p className="subtitle">
          Historical Logs & Trends 
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
          <button onClick={() => fetchAnalyticsData(false)} disabled={loading}>
            Try Again
          </button>
        </div>
      )}

      {/* Export and Refresh Buttons */}
      <div className="export-section">
        <button 
          className="export-btn refresh-btn" 
          onClick={() => fetchAnalyticsData(false)} 
          disabled={loading}
        >
          <FiRefreshCw className={loading ? 'spinning' : ''} /> 
          {loading ? 'Loading...' : 'Refresh Data'}
        </button>
        <button className="export-btn" onClick={() => exportLogs('csv')}>
          <FiDownload /> Export as CSV
        </button>
      </div>

      {/* Trends & Visualizations */}
      <div className="charts-grid">
        <div className="chart-card">
          <h3><FiTrendingUp /> Threats Per Day</h3>
          <ResponsiveContainer width="100%" height={250}>
            <LineChart data={threatsPerDay}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="date" />
              <YAxis />
              <Tooltip />
              <Legend />
              <Line type="monotone" dataKey="threats" stroke="#F44336" strokeWidth={2} />
            </LineChart>
          </ResponsiveContainer>
        </div>

        <div className="chart-card">
          <h3><FiTrendingUp /> Device Count Over Time</h3>
          <ResponsiveContainer width="100%" height={250}>
            <LineChart data={deviceActivity}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="date" />
              <YAxis />
              <Tooltip />
              <Legend />
              <Line type="monotone" dataKey="devices" stroke="#2196F3" strokeWidth={2} />
            </LineChart>
          </ResponsiveContainer>
        </div>

        <div className="chart-card full-width">
          <h3><FiTrendingUp /> Most Active Devices</h3>
          <ResponsiveContainer width="100%" height={250}>
            <BarChart data={mostActiveDevices}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="name" />
              <YAxis />
              <Tooltip />
              <Legend />
              <Bar dataKey="packets" fill="#9C27B0" />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Logs Table */}
      <div className="logs-section">
        <h2>Activity Logs</h2>
        <div className="logs-table">
          <table>
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Type</th>
                <th>Message</th>
                <th>Details</th>
              </tr>
            </thead>
            <tbody>
              {(logs.length === 0 ? EXAMPLE_LOGS : logs).map(log => (
                <tr key={log.id}>
                  <td>{formatTimestamp(log.timestamp)}</td>
                  <td>
                    <span 
                      className="type-badge"
                      style={{ backgroundColor: getTypeColor(log.type) }}
                    >
                      {log.type}
                    </span>
                  </td>
                  <td>{log.message}</td>
                  <td>{log.details}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

export default Analytics;
