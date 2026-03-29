import React from 'react';
import { PacketData } from '../types/packet';
import './PacketTable.css';

interface PacketTableProps {
  packets: PacketData[];
  onPacketSelect?: (packet: PacketData) => void;
}

const PacketTable: React.FC<PacketTableProps> = ({ packets, onPacketSelect }) => {
  const formatTimestamp = (timestamp: string) => {
    return new Date(timestamp).toLocaleString();
  };

  const getProtocolColor = (protocol: string) => {
    const colors: { [key: string]: string } = {
      'TCP': '#4CAF50',
      'UDP': '#2196F3',
      'HTTP': '#FF9800',
      'HTTPS': '#F44336',
      'ICMP': '#9C27B0',
      'FTP': '#795548',
      'SSH': '#607D8B'
    };
    return colors[protocol] || '#666';
  };

  return (
    <div className="packet-table-container">
      <table className="packet-table">
        <thead>
          <tr>
            <th>ID</th>
            <th>Timestamp</th>
            <th>Protocol</th>
            <th>Source</th>
            <th>Destination</th>
            <th>Hostname</th>
            <th>Length</th>
            <th>Flags</th>
          </tr>
        </thead>
        <tbody>
          {packets.map((packet) => (
            <tr 
              key={packet.id} 
              onClick={() => onPacketSelect?.(packet)}
              className="packet-row"
            >
              <td>{packet.id}</td>
              <td className="timestamp">{formatTimestamp(packet.timestamp)}</td>
              <td>
                <span 
                  className="protocol-badge"
                  style={{ backgroundColor: getProtocolColor(packet.protocol) }}
                >
                  {packet.protocol}
                </span>
              </td>
              <td>{packet.sourceIP}:{packet.sourcePort}</td>
              <td>{packet.destIP}:{packet.destPort}</td>
              <td className="hostname">{packet.hostname || '-'}</td>
              <td>{packet.length} bytes</td>
              <td>{packet.flags || '-'}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {packets.length === 0 && (
        <div className="empty-state">
          No packets found. Check your filters or try refreshing the data.
        </div>
      )}
    </div>
  );
};

export default PacketTable;