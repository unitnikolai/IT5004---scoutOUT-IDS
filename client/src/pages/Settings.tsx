import React, { useState, useEffect } from 'react';
import { FiUser, FiBell, FiMoon, FiDatabase, FiSettings } from 'react-icons/fi';
import { useTheme } from '../ThemeContext';
import './Settings.css';

const getApiUrl = (): string => {
  if (process.env.REACT_APP_API_URL) return process.env.REACT_APP_API_URL;
  const { protocol, hostname } = window.location;
  return `${protocol}//${hostname}:5050/api`;
};

const API_BASE_URL = getApiUrl();

const Settings: React.FC = () => {
  const { theme, setTheme } = useTheme();
  const [emailAlerts, setEmailAlerts] = useState(true);
  const [smsAlerts, setSmsAlerts] = useState(false);
  const [severityThreshold, setSeverityThreshold] = useState('medium');
  const [dataRetention, setDataRetention] = useState(30);
  const [updateFrequency, setUpdateFrequency] = useState(5);
  const [virusTotalApiKey, setVirusTotalApiKey] = useState('');
  const [vtKeyConfigured, setVtKeyConfigured] = useState(false);
  const [vtSaveStatus, setVtSaveStatus] = useState<'idle' | 'saving' | 'saved' | 'error'>('idle');

  // On mount: check if the server already has a key configured, and pre-fill
  // from localStorage so the user can see what they last entered.
  useEffect(() => {
    const stored = localStorage.getItem('vt_api_key_hint') || '';
    if (stored) setVirusTotalApiKey(stored);

    fetch(`${API_BASE_URL}/settings/virustotal-key/status`)
      .then((r) => r.json())
      .then((d) => setVtKeyConfigured(d.configured || false))
      .catch(() => {});
  }, []);

  const handleThemeChange = (newTheme: 'light' | 'dark') => {
    setTheme(newTheme);
  };

  const saveVirusTotalKey = async () => {
    if (!virusTotalApiKey.trim()) return;
    setVtSaveStatus('saving');
    try {
      const res = await fetch(`${API_BASE_URL}/settings/virustotal-key`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ apiKey: virusTotalApiKey.trim() }),
      });
      if (!res.ok) throw new Error('Server error');
      // Store a hint in localStorage so the field stays populated on reload
      localStorage.setItem('vt_api_key_hint', virusTotalApiKey.trim());
      setVtKeyConfigured(true);
      setVtSaveStatus('saved');
      setTimeout(() => setVtSaveStatus('idle'), 3000);
    } catch {
      setVtSaveStatus('error');
      setTimeout(() => setVtSaveStatus('idle'), 3000);
    }
  };

  const handleSave = () => {
    saveVirusTotalKey();
    alert('Settings saved successfully!');
  };

  return (
    <div className="settings-page">
      <div className="page-header">
        <h1>Settings</h1>
        <p className="subtitle">System Configuration</p>
      </div>

      <div className="settings-grid">
        {/* Account Settings */}
        <div className="settings-card">
          <div className="card-header">
            <FiUser size={20} />
            <h3>Account Settings</h3>
          </div>
          <div className="card-content">
            <div className="form-group">
              <label>Email Address</label>
              <input type="email" defaultValue="user@example.com" />
            </div>
            <div className="form-group">
              <label>Current Password</label>
              <input type="password" placeholder="Enter current password" />
            </div>
            <div className="form-group">
              <label>New Password</label>
              <input type="password" placeholder="Enter new password" />
            </div>
          </div>
        </div>

        {/* Notifications */}
        <div className="settings-card">
          <div className="card-header">
            <FiBell size={20} />
            <h3>Notifications</h3>
          </div>
          <div className="card-content">
            <div className="form-group">
              <label className="checkbox-label">
                <input 
                  type="checkbox" 
                  checked={emailAlerts}
                  onChange={(e) => setEmailAlerts(e.target.checked)}
                />
                <span>Email Alerts</span>
              </label>
            </div>
            <div className="form-group">
              <label className="checkbox-label">
                <input 
                  type="checkbox" 
                  checked={smsAlerts}
                  onChange={(e) => setSmsAlerts(e.target.checked)}
                />
                <span>SMS Alerts</span>
              </label>
            </div>
            <div className="form-group">
              <label>Severity Threshold</label>
              <select value={severityThreshold} onChange={(e) => setSeverityThreshold(e.target.value)}>
                <option value="low">Low</option>
                <option value="medium">Medium</option>
                <option value="high">High</option>
                <option value="critical">Critical</option>
              </select>
            </div>
          </div>
        </div>

        {/* Theme Appearance */}
        <div className="settings-card">
          <div className="card-header">
            <FiMoon size={20} />
            <h3>Theme Appearance</h3>
          </div>
          <div className="card-content">
            <div className="theme-options">
              <label className="theme-option">
                <input 
                  type="radio" 
                  name="theme" 
                  value="light"
                  checked={theme === 'light'}
                  onChange={(e) => handleThemeChange(e.target.value as 'light' | 'dark')}
                />
                <span className="theme-preview light-theme">
                  <div className="preview-header"></div>
                  <div className="preview-content"></div>
                </span>
                <span>Light Mode</span>
              </label>
              <label className="theme-option">
                <input 
                  type="radio" 
                  name="theme" 
                  value="dark"
                  checked={theme === 'dark'}
                  onChange={(e) => handleThemeChange(e.target.value as 'light' | 'dark')}
                />
                <span className="theme-preview dark-theme">
                  <div className="preview-header"></div>
                  <div className="preview-content"></div>
                </span>
                <span>Dark Mode</span>
              </label>
            </div>
          </div>
        </div>

        {/* Data Retention */}
        <div className="settings-card">
          <div className="card-header">
            <FiDatabase size={20} />
            <h3>Data Retention Policies</h3>
          </div>
          <div className="card-content">
            <div className="form-group">
              <label>Delete Logs After (Days)</label>
              <input 
                type="number" 
                value={dataRetention}
                onChange={(e) => setDataRetention(parseInt(e.target.value))}
                min="1"
                max="365"
              />
            </div>
            <div className="form-group">
              <label className="checkbox-label">
                <input type="checkbox" />
                <span>Local-Only Storage</span>
              </label>
              <p className="help-text">Keep all data on local device only</p>
            </div>
          </div>
        </div>

        {/* System Preferences */}
        <div className="settings-card">
          <div className="card-header">
            <FiSettings size={20} />
            <h3>System Preferences</h3>
          </div>
          <div className="card-content">
            <div className="form-group">
              <label>Update Frequency (minutes)</label>
              <input 
                type="number" 
                value={updateFrequency}
                onChange={(e) => setUpdateFrequency(parseInt(e.target.value))}
                min="1"
                max="60"
              />
            </div>
            <div className="form-group">
              <label>Network Refresh Interval (seconds)</label>
              <input type="number" defaultValue="10" min="1" max="60" />
            </div>
          </div>
        </div>

        {/* Integrations */}
        <div className="settings-card">
          <div className="card-header">
            <FiSettings size={20} />
            <h3>Integrations</h3>
          </div>
          <div className="card-content">
            <div className="form-group">
              <label>VirusTotal API Key
                {vtKeyConfigured && (
                  <span style={{ marginLeft: 8, color: '#4caf50', fontSize: '0.78em' }}>✓ Active on server</span>
                )}
              </label>
              <input 
                type="password"
                value={virusTotalApiKey}
                onChange={(e) => setVirusTotalApiKey(e.target.value)}
                placeholder="Enter your VirusTotal API key"
              />
              <p className="help-text">
                Get your free API key from{' '}
                <a href="https://www.virustotal.com" target="_blank" rel="noopener noreferrer">virustotal.com</a>.{' '}
                All unique public HTTPS source IPs are automatically screened against VirusTotal on the Threats page.
              </p>
              <button
                onClick={saveVirusTotalKey}
                disabled={vtSaveStatus === 'saving' || !virusTotalApiKey.trim()}
                style={{ marginTop: 8 }}
              >
                {vtSaveStatus === 'saving' ? 'Saving…'
                  : vtSaveStatus === 'saved' ? '✓ Saved'
                  : vtSaveStatus === 'error' ? '✗ Error — try again'
                  : 'Apply API Key'}
              </button>
            </div>
            <div className="form-group">
              <label>Router Model</label>
              <select>
                <option>Generic Router</option>
                <option>TP-Link</option>
                <option>Netgear</option>
                <option>ASUS</option>
                <option>Linksys</option>
              </select>
            </div>
          </div>
        </div>
      </div>

      {/* Save Button */}
      <div className="settings-actions">
        <button className="save-button" onClick={handleSave}>
          Save All Settings
        </button>
      </div>
    </div>
  );
};

export default Settings;
