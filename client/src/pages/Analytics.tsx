import React, { useState, useEffect } from 'react';
import { FiDownload, FiTrendingUp, FiRefreshCw } from 'react-icons/fi';
import { LineChart, Line, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts';
import analyticsService, { LogEntry, TimeSeriesData, TopDevice } from '../services/analyticsService';
import './Analytics.css';

const Analytics: React.FC = () => {
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [threatsPerDay, setThreatsPerDay] = useState<TimeSeriesData[]>([]);
  const [deviceActivity, setDeviceActivity] = useState<TimeSeriesData[]>([]);
  const [mostActiveDevices, setMostActiveDevices] = useState<TopDevice[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);

  const fetchAnalyticsData = async () => {
    try {
      setLoading(true);
      setError(null);

      const [logsResponse, threatsResponse, devicesResponse, topDevicesResponse] = await Promise.all([
        analyticsService.getLogs(),
        analyticsService.getThreatsTimeline(),
        analyticsService.getDeviceActivity(),
        analyticsService.getTopDevices()
      ]);

      setLogs(logsResponse.logs || []);
      setThreatsPerDay(threatsResponse.data || []);
      setDeviceActivity(devicesResponse.data || []);
      setMostActiveDevices(topDevicesResponse.data || []);
      setLastUpdated(new Date());
    } catch (err: any) {
      // Silently ignore abort errors (user navigated away)
      const isAbortError = err?.code === 'ECONNABORTED' || err?.name === 'AbortError' || err?.message?.includes('cancel');
      if (!isAbortError) {
        console.error('Failed to fetch analytics data:', err);
        setError('Failed to load analytics data. Please try again.');
      }
      // Keep existing data if available
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAnalyticsData();
    // Cleanup: cancel pending requests when component unmounts
    return () => {
      analyticsService.cancelRequests?.();
    };
  }, []);

  const exportLogs = (format: 'csv' | 'pdf') => {
    alert(`Exporting logs as ${format.toUpperCase()}...`);
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
          <button onClick={fetchAnalyticsData} disabled={loading}>
            Try Again
          </button>
        </div>
      )}

      {/* Export and Refresh Buttons */}
      <div className="export-section">
        <button 
          className="export-btn refresh-btn" 
          onClick={fetchAnalyticsData} 
          disabled={loading}
        >
          <FiRefreshCw className={loading ? 'spinning' : ''} /> 
          {loading ? 'Loading...' : 'Refresh Data'}
        </button>
        <button className="export-btn" onClick={() => exportLogs('csv')}>
          <FiDownload /> Export as CSV
        </button>
        <button className="export-btn" onClick={() => exportLogs('pdf')}>
          <FiDownload /> Export as PDF
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
              {logs.map(log => (
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
