import React, { useState } from 'react';
import { FiShield, FiClock, FiUser, FiBarChart2 } from 'react-icons/fi';
import './ParentalControls.css';

interface Device {
  id: number;
  name: string;
  user: string;
}

interface BlockedSite {
  id: number;
  url: string;
  timestamp: string;
  device: string;
}

const ParentalControls: React.FC = () => {
  const [blockedUrls, setBlockedUrls] = useState<string[]>(['example-gambling.com', 'adult-content.net']);
  const [newUrl, setNewUrl] = useState('');
  const [categories, setCategories] = useState({
    adult: true,
    gambling: true,
    social: false,
    violence: true,
    untrusted: true
  });

  const [devices] = useState<Device[]>([
    { id: 1, name: 'iPhone-12', user: 'Child' },
    { id: 2, name: 'Gaming-PC', user: 'Child' },
    { id: 3, name: 'iPad-Pro', user: 'Parent' }
  ]);

  const [schedules] = useState([
    { device: 'Gaming-PC', time: '22:00', days: ['Mon', 'Tue', 'Wed', 'Thu', 'Fri'] },
    { device: 'iPhone-12', time: '21:00', days: ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'] }
  ]);

  const [blockedActivity] = useState<BlockedSite[]>([
    { id: 1, url: 'gaming-site.com', timestamp: new Date().toISOString(), device: 'Gaming-PC' },
    { id: 2, url: 'social-media.com', timestamp: new Date(Date.now() - 3600000).toISOString(), device: 'iPhone-12' }
  ]);

  const addBlockedUrl = () => {
    if (newUrl && !blockedUrls.includes(newUrl)) {
      setBlockedUrls([...blockedUrls, newUrl]);
      setNewUrl('');
    }
  };

  const removeBlockedUrl = (url: string) => {
    setBlockedUrls(blockedUrls.filter(u => u !== url));
  };

  const toggleCategory = (category: keyof typeof categories) => {
    setCategories({ ...categories, [category]: !categories[category] });
  };

  const formatTimestamp = (timestamp: string) => {
    return new Date(timestamp).toLocaleString();
  };

  return (
    <div className="parental-controls-page">
      <div className="page-header">
        <h1>Parental Controls</h1>
        <p className="subtitle">Manage Online Safety Settings</p>
      </div>

      <div className="controls-grid">
        {/* Website Blocking */}
        <div className="control-card">
          <div className="card-header">
            <FiShield size={20} />
            <h3>Website Blocking</h3>
          </div>
          <div className="card-content">
            <div className="url-input-group">
              <input
                type="text"
                placeholder="Enter domain to block (e.g., example.com)"
                value={newUrl}
                onChange={(e) => setNewUrl(e.target.value)}
                onKeyPress={(e) => e.key === 'Enter' && addBlockedUrl()}
              />
              <button onClick={addBlockedUrl}>Block</button>
            </div>
            <div className="blocked-urls-list">
              {blockedUrls.map(url => (
                <div key={url} className="blocked-url-item">
                  <span>{url}</span>
                  <button onClick={() => removeBlockedUrl(url)}>Remove</button>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Category Filtering */}
        <div className="control-card">
          <div className="card-header">
            <FiShield size={20} />
            <h3>Category Filtering</h3>
          </div>
          <div className="card-content">
            <div className="category-list">
              <label className="category-item">
                <input
                  type="checkbox"
                  checked={categories.adult}
                  onChange={() => toggleCategory('adult')}
                />
                <span>Adult Content</span>
              </label>
              <label className="category-item">
                <input
                  type="checkbox"
                  checked={categories.gambling}
                  onChange={() => toggleCategory('gambling')}
                />
                <span>Gambling</span>
              </label>
              <label className="category-item">
                <input
                  type="checkbox"
                  checked={categories.social}
                  onChange={() => toggleCategory('social')}
                />
                <span>Social Media</span>
              </label>
              <label className="category-item">
                <input
                  type="checkbox"
                  checked={categories.violence}
                  onChange={() => toggleCategory('violence')}
                />
                <span>Violence</span>
              </label>
              <label className="category-item">
                <input
                  type="checkbox"
                  checked={categories.untrusted}
                  onChange={() => toggleCategory('untrusted')}
                />
                <span>Untrusted Websites</span>
              </label>
            </div>
          </div>
        </div>

        {/* Time-Based Restrictions */}
        <div className="control-card">
          <div className="card-header">
            <FiClock size={20} />
            <h3>Time-Based Restrictions</h3>
          </div>
          <div className="card-content">
            <div className="schedules-list">
              {schedules.map((schedule, idx) => (
                <div key={idx} className="schedule-item">
                  <div className="schedule-info">
                    <strong>{schedule.device}</strong>
                    <span>Cutoff: {schedule.time}</span>
                    <span className="days">{schedule.days.join(', ')}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Per-Device Rules */}
        <div className="control-card">
          <div className="card-header">
            <FiUser size={20} />
            <h3>Per-Device Rules</h3>
          </div>
          <div className="card-content">
            <div className="devices-list">
              {devices.map(device => (
                <div key={device.id} className="device-rule-item">
                  <div className="device-rule-info">
                    <strong>{device.name}</strong>
                    <span>Assigned to: {device.user}</span>
                  </div>
                  <button className="edit-button">Edit Rules</button>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Activity Reports */}
        <div className="control-card wide-card">
          <div className="card-header">
            <FiBarChart2 size={20} />
            <h3>Activity Reports</h3>
          </div>
          <div className="card-content">
            <div className="activity-table">
              <table>
                <thead>
                  <tr>
                    <th>Blocked Site</th>
                    <th>Device</th>
                    <th>Timestamp</th>
                  </tr>
                </thead>
                <tbody>
                  {blockedActivity.map(activity => (
                    <tr key={activity.id}>
                      <td>{activity.url}</td>
                      <td>{activity.device}</td>
                      <td>{formatTimestamp(activity.timestamp)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ParentalControls;
