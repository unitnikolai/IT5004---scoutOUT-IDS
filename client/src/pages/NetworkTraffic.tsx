import React, { useState } from 'react';
import PacketTable from '../components/PacketTable';
import { PacketData } from '../types/packet';
import { FiPlay, FiPause } from 'react-icons/fi';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts';
import './NetworkTraffic.css';

const NetworkTraffic: React.FC = () => {
  const [isCapturing, setIsCapturing] = useState(true);
  const [filterDevice, setFilterDevice] = useState('');
  const [filterProtocol, setFilterProtocol] = useState('');
  const [threatsOnly, setThreatsOnly] = useState(false);

  const [packets] = useState<PacketData[]>([
    {
      id: 1,
      timestamp: new Date().toISOString(),
      protocol: 'TCP',
      sourceIP: '192.168.1.100',
      destIP: '8.8.8.8',
      sourcePort: 54321,
      destPort: 443,
      length: 1024,
      payload: 'Sample payload'
    }
  ]);

  const [protocolData] = useState([
    { name: 'TCP', value: 45, color: '#4CAF50' },
    { name: 'UDP', value: 30, color: '#2196F3' },
    { name: 'HTTP', value: 15, color: '#FF9800' },
    { name: 'HTTPS', value: 10, color: '#F44336' }
  ]);

  const [bandwidthData] = useState([
    { device: 'Gaming-PC', bandwidth: 850 },
    { device: 'iPhone-12', bandwidth: 450 },
    { device: 'Smart-TV', bandwidth: 620 },
    { device: 'Laptop', bandwidth: 380 },
    { device: 'IoT-Camera', bandwidth: 120 }
  ]);

  const toggleCapture = () => {
    setIsCapturing(!isCapturing);
  };

  return (
    <div className="network-traffic-page">
      <div className="page-header">
        <h1>Network Traffic</h1>
        <p className="subtitle">Real-time Packet Analysis</p>
      </div>

      {/* Capture Controls */}
      <div className="traffic-controls">
        <button 
          className={`capture-button ${isCapturing ? 'capturing' : 'paused'}`}
          onClick={toggleCapture}
        >
          {isCapturing ? <><FiPause /> Pause Capture</> : <><FiPlay /> Resume Capture</>}
        </button>
        
        <div className="traffic-filters">
          <select value={filterDevice} onChange={(e) => setFilterDevice(e.target.value)}>
            <option value="">All Devices</option>
            <option value="192.168.1.100">Gaming-PC (192.168.1.100)</option>
            <option value="192.168.1.105">iPhone-12 (192.168.1.105)</option>
            <option value="192.168.1.110">Smart-TV (192.168.1.110)</option>
          </select>

          <select value={filterProtocol} onChange={(e) => setFilterProtocol(e.target.value)}>
            <option value="">All Protocols</option>
            <option value="TCP">TCP</option>
            <option value="UDP">UDP</option>
            <option value="HTTP">HTTP</option>
            <option value="HTTPS">HTTPS</option>
          </select>

          <label className="checkbox-filter">
            <input 
              type="checkbox" 
              checked={threatsOnly}
              onChange={(e) => setThreatsOnly(e.target.checked)}
            />
            <span>Threats Only</span>
          </label>
        </div>
      </div>

      {/* Charts */}
      <div className="traffic-charts">
        <div className="chart-card">
          <h3>Protocol Distribution</h3>
          <ResponsiveContainer width="100%" height={250}>
            <PieChart>
              <Pie
                data={protocolData}
                cx="50%"
                cy="50%"
                labelLine={false}
                label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                outerRadius={80}
                fill="#8884d8"
                dataKey="value"
              >
                {protocolData.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip />
            </PieChart>
          </ResponsiveContainer>
        </div>

        <div className="chart-card">
          <h3>Bandwidth Usage by Device</h3>
          <ResponsiveContainer width="100%" height={250}>
            <BarChart data={bandwidthData}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="device" angle={-45} textAnchor="end" height={100} />
              <YAxis />
              <Tooltip />
              <Bar dataKey="bandwidth" fill="#2196F3" />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Packet Table */}
      <div className="packets-section">
        <h2>Live Packet Stream</h2>
        <PacketTable packets={packets} />
      </div>
    </div>
  );
};

export default NetworkTraffic;
