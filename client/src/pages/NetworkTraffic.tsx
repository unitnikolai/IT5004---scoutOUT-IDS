import React, { useState, useEffect } from 'react';
import PacketTable from '../components/PacketTable';
import { PacketData } from '../types/packet';
import packetService from '../services/packetService';
import { FiPlay, FiPause } from 'react-icons/fi';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts';
import './NetworkTraffic.css';

interface ProtocolData {
  name: string;
  value: number;
  color: string;
  [key: string]: string | number;
}

interface BandwidthData {
  device: string;
  bandwidth: number;
  [key: string]: string | number;
}

const NetworkTraffic: React.FC = () => {
  const [isCapturing, setIsCapturing] = useState(true);
  const [filterDevice, setFilterDevice] = useState('');
  const [filterProtocol, setFilterProtocol] = useState('');
  const [threatsOnly, setThreatsOnly] = useState(false);

  const [packets, setPackets] = useState<PacketData[]>([]);
  const [protocolData, setProtocolData] = useState<ProtocolData[]>([]);
  const [bandwidthData, setBandwidthData] = useState<BandwidthData[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [lastPacketCount, setLastPacketCount] = useState(0);

  const colorMap: Record<string, string> = {
    'TCP': '#4CAF50',
    'UDP': '#2196F3',
    'HTTP': '#FF9800',
    'HTTPS': '#F44336',
    'DNS': '#E91E63',
    'ICMP': '#9C27B0',
    'NTP': '#673AB7',
    'DHCP': '#3F51B5',
    'Unknown': '#999999'
  };

  const fetchPackets = async () => {
    try {
      setLoading(true);
      setError(null);
      const response = await packetService.getPackets({ limit: 500 });
      const fetchedPackets = response.packets || [];
      
      // Only update if packet count changed (new packets arrived)
      if (fetchedPackets.length !== lastPacketCount) {
        setLastPacketCount(fetchedPackets.length);
        setPackets(fetchedPackets);
        
        // Calculate protocol distribution
        const protocolCounts: Record<string, number> = {};
        fetchedPackets.forEach(packet => {
          const proto = packet.protocol || 'Unknown';
          protocolCounts[proto] = (protocolCounts[proto] || 0) + 1;
        });
        
        const protocolChart = Object.entries(protocolCounts).map(([name, value]) => ({
          name,
          value,
          color: colorMap[name] || '#999999'
        }));
        setProtocolData(protocolChart);
        
        // Calculate bandwidth by device (source IP)
        const bandwidthCounts: Record<string, number> = {};
        fetchedPackets.forEach(packet => {
          const ip = packet.sourceIP || 'Unknown';
          bandwidthCounts[ip] = (bandwidthCounts[ip] || 0) + packet.length;
        });
        
        const bandwidthChart = Object.entries(bandwidthCounts)
          .map(([device, bandwidth]) => ({
            device,
            bandwidth: Math.round(bandwidth / 1024) // Convert to KB
          }))
          .sort((a, b) => b.bandwidth - a.bandwidth)
          .slice(0, 5); // Top 5 devices
        
        setBandwidthData(bandwidthChart);
      }
    } catch (err) {
      console.error('Failed to fetch packets:', err);
      setError('Failed to load packets');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchPackets();
    
    // Poll for new packets every 5 seconds (only updates if count changed)
    const interval = setInterval(() => {
      if (isCapturing) {
        fetchPackets();
      }
    }, 5000);
    
    return () => clearInterval(interval);
  }, [isCapturing]);

  const toggleCapture = () => {
    setIsCapturing(!isCapturing);
  };

  const filteredPackets = packets.filter(packet => {
    if (filterDevice && packet.sourceIP !== filterDevice) return false;
    if (filterProtocol && packet.protocol.toLowerCase() !== filterProtocol.toLowerCase()) return false;
    return true;
  });

  return (
    <div className="network-traffic-page">
      <div className="page-header">
        <h1>Network Traffic</h1>
        <p className="subtitle">Real-time Packet Analysis</p>
      </div>

      {error && <div className="error-banner">{error}</div>}

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
            {Array.from(new Set(packets.map(p => p.sourceIP))).map(ip => (
              <option key={ip} value={ip}>{ip}</option>
            ))}
          </select>

          <select value={filterProtocol} onChange={(e) => setFilterProtocol(e.target.value)}>
            <option value="">All Protocols</option>
            {Array.from(new Set(packets.map(p => p.protocol))).map(proto => (
              <option key={proto} value={proto}>{proto}</option>
            ))}
          </select>
        </div>

        <div className="packets-count">
          {loading ? 'Loading...' : `${filteredPackets.length} packets loaded`}
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
              <XAxis dataKey="device" angle={-45} textAnchor="end" height={80} />
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
        {loading ? (
          <p>Loading packets...</p>
        ) : filteredPackets.length === 0 ? (
          <p>No packets captured yet. Start capturing to see data.</p>
        ) : (
          <PacketTable packets={filteredPackets} />
        )}
      </div>
    </div>
  );
};

export default NetworkTraffic;
