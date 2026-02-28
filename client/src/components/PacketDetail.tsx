import React from 'react';
import { PacketData } from '../types/packet';
import './PacketDetail.css';

interface PacketDetailProps {
  packet: PacketData | null;
  isOpen: boolean;
  onClose: () => void;
}

const PacketDetail: React.FC<PacketDetailProps> = ({ packet, isOpen, onClose }) => {
  if (!isOpen || !packet) return null;

  const formatTimestamp = (timestamp: string) => {
    return new Date(timestamp).toLocaleString();
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="packet-detail-modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <h2>Packet Details - ID: {packet.id}</h2>
          <button className="close-button" onClick={onClose}>×</button>
        </div>
        
        <div className="modal-content">
          <div className="detail-grid">
            <div className="detail-item">
              <label>Timestamp:</label>
              <span>{formatTimestamp(packet.timestamp)}</span>
            </div>
            
            <div className="detail-item">
              <label>Protocol:</label>
              <span className="protocol-value">{packet.protocol}</span>
            </div>
            
            <div className="detail-item">
              <label>Source IP:</label>
              <span>{packet.sourceIP}</span>
            </div>
            
            <div className="detail-item">
              <label>Source Port:</label>
              <span>{packet.sourcePort}</span>
            </div>
            
            <div className="detail-item">
              <label>Destination IP:</label>
              <span>{packet.destIP}</span>
            </div>
            
            <div className="detail-item">
              <label>Destination Port:</label>
              <span>{packet.destPort}</span>
            </div>
            
            <div className="detail-item">
              <label>Length:</label>
              <span>{packet.length} bytes</span>
            </div>
            
            <div className="detail-item">
              <label>Flags:</label>
              <span>{packet.flags || 'None'}</span>
            </div>
          </div>
          
          <div className="payload-section">
            <label>Payload:</label>
            <div className="payload-content">
              {packet.payload}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default PacketDetail;