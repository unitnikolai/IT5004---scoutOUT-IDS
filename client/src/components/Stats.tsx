import React from 'react';
import { StatsData } from '../types/packet';
import './Stats.css';

interface StatsProps {
  stats: StatsData;
}

const Stats: React.FC<StatsProps> = ({ stats }) => {
  const formatDateTime = (dateString?: string) => {
    if (!dateString) return 'N/A';
    return new Date(dateString).toLocaleString();
  };

  return (
    <div className="stats-container">
      <h2>Network Statistics</h2>
      
      <div className="stats-grid">
        <div className="stat-card">
          <h3>Total Packets</h3>
          <p className="stat-value">{stats.totalPackets}</p>
        </div>
        
        <div className="stat-card">
          <h3>Average Packet Size</h3>
          <p className="stat-value">{stats.averagePacketSize} bytes</p>
        </div>
        
        <div className="stat-card">
          <h3>Time Range</h3>
          <p className="stat-detail">
            <strong>Latest:</strong> {formatDateTime(stats.timeRange.latest)}
          </p>
          <p className="stat-detail">
            <strong>Earliest:</strong> {formatDateTime(stats.timeRange.earliest)}
          </p>
        </div>
      </div>
      
      <div className="protocol-distribution">
        <h3>Protocol Distribution</h3>
        <div className="protocol-chart">
          {Object.entries(stats.protocolDistribution).map(([protocol, count]) => {
            const percentage = ((count / stats.totalPackets) * 100).toFixed(1);
            return (
              <div key={protocol} className="protocol-bar">
                <div className="protocol-label">
                  <span>{protocol}</span>
                  <span>{count} ({percentage}%)</span>
                </div>
                <div className="protocol-progress">
                  <div 
                    className="protocol-fill"
                    style={{ width: `${percentage}%` }}
                  />
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};

export default Stats;