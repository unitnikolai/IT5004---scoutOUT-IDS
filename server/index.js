const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const { addPacket, getPackets } = require('./packetStore.js');
const app = express();
const PORT = process.env.PORT || 5050;

// Middleware
app.use(cors());
app.use(express.json());

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});
app.use('/api/', limiter);

// Mock packet capture data

// Routes
app.get('/api/health', (req, res) => {
  res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

app.post('/api/packets', (req, res) => {
  addPacket(req.body);
  res.status(201).json({ status: 'ok'})
}
)

app.get('/api/packets', (req, res) => {
  const { limit = 50, protocol, sourceIP, destIP } = req.query;
  let packets = getPackets()
  
  // Apply filters
  if (protocol) {
    packets = packets.filter(p => p.protocol.toLowerCase() === protocol.toLowerCase());
  }
  if (sourceIP) {
    packets = packets.filter(p => p.sourceIP === sourceIP);
  }
  if (destIP) {
    packets = packets.filter(p => p.destIP === destIP);
  }
  
  // Apply limit
  packets = packets.slice(0, parseInt(limit));
  
  res.json({
    packets,
    total: packets.length,
    timestamp: new Date().toISOString()
  });
});

app.get('/api/packets/:id', (req, res) => {
  const { id } = req.params;
  const packets = generateMockPackets(100);
  const packet = packets.find(p => p.id === parseInt(id));
  
  if (!packet) {
    return res.status(404).json({ error: 'Packet not found' });
  }
  
  res.json(packet);
});

app.get('/api/stats', (req, res) => {
  const packets = getPackets(); // Use real packets instead of mock
  const stats = {
    totalPackets: packets.length,
    protocolDistribution: {},
    averagePacketSize: 0,
    timeRange: {
      earliest: packets[packets.length - 1]?.timestamp,
      latest: packets[0]?.timestamp
    }
  };
  
  // Calculate protocol distribution
  packets.forEach(packet => {
    stats.protocolDistribution[packet.protocol] = 
      (stats.protocolDistribution[packet.protocol] || 0) + 1;
  });
  
  // Calculate average packet size
  if (packets.length > 0) {
    stats.averagePacketSize = Math.round(
      packets.reduce((sum, packet) => sum + packet.length, 0) / packets.length
    );
  }
  
  res.json(stats);
});

// Analytics functions
const analyzePacketsForThreats = (packets) => {
  const suspiciousPorts = [22, 23, 135, 139, 445, 1433, 3389]; // Common attack vectors
  const suspiciousDomains = ['malware.example.com', 'phishing-site.com', 'botnet.example.org'];
  const threats = [];

  packets.forEach(packet => {
    let threatType = '';
    let severity = 'low';
    let message = '';

    // Check for suspicious ports
    if (suspiciousPorts.includes(packet.destPort)) {
      threatType = 'port-scan';
      severity = packet.destPort === 22 || packet.destPort === 3389 ? 'high' : 'medium';
      message = `Suspicious connection to port ${packet.destPort}`;
    }

    // Check for unusual packet sizes (potential DDoS)
    if (packet.length > 1400) {
      threatType = 'large-packet';
      severity = 'medium';
      message = `Unusually large packet detected (${packet.length} bytes)`;
    }

    // Check for rapid connections from same IP
    const sameSourcePackets = packets.filter(p => 
      p.sourceIP === packet.sourceIP && 
      Math.abs(new Date(p.timestamp) - new Date(packet.timestamp)) < 1000
    );
    if (sameSourcePackets.length > 10) {
      threatType = 'dos-attempt';
      severity = 'critical';
      message = `Potential DoS attack from ${packet.sourceIP}`;
    }

    if (threatType) {
      threats.push({
        id: Date.now() + Math.random(),
        timestamp: packet.timestamp,
        type: 'threat',
        message: message,
        details: `${severity.toUpperCase()} severity - ${threatType}`,
        sourceIP: packet.sourceIP,
        destIP: packet.destIP,
        severity
      });
    }
  });

  return threats;
};

const analyzeDeviceActivity = (packets) => {
  const deviceMap = new Map();
  
  packets.forEach(packet => {
    const deviceKey = packet.sourceIP;
    if (!deviceMap.has(deviceKey)) {
      deviceMap.set(deviceKey, {
        ip: packet.sourceIP,
        lastSeen: packet.timestamp,
        packetCount: 0,
        protocols: new Set(),
        totalBytes: 0
      });
    }
    
    const device = deviceMap.get(deviceKey);
    device.packetCount++;
    device.totalBytes += packet.length;
    device.protocols.add(packet.protocol);
    
    if (new Date(packet.timestamp) > new Date(device.lastSeen)) {
      device.lastSeen = packet.timestamp;
    }
  });

  return Array.from(deviceMap.values()).map(device => ({
    ...device,
    protocols: Array.from(device.protocols)
  }));
};

const generateActivityLogs = (packets) => {
  const logs = [];
  const threats = analyzePacketsForThreats(packets);
  const devices = analyzeDeviceActivity(packets);
  
  // Add threat logs
  threats.slice(0, 10).forEach(threat => {
    logs.push({
      id: threat.id,
      timestamp: threat.timestamp,
      type: 'threat',
      message: threat.message,
      details: threat.details
    });
  });

  // Add device connection logs
  devices.slice(0, 5).forEach((device, index) => {
    logs.push({
      id: Date.now() + index,
      timestamp: device.lastSeen,
      type: 'device',
      message: `Device activity: ${device.ip}`,
      details: `${device.packetCount} packets, ${device.totalBytes} bytes`
    });
  });

  // Add parental control simulated logs
  const parentalLogs = [
    { category: 'gaming', site: 'gaming-site.com' },
    { category: 'social', site: 'social-network.com' },
    { category: 'streaming', site: 'video-stream.com' }
  ];

  parentalLogs.forEach((log, index) => {
    logs.push({
      id: Date.now() + index + 1000,
      timestamp: new Date(Date.now() - Math.random() * 3600000 * 24).toISOString(),
      type: 'parental',
      message: `Blocked ${log.site}`,
      details: `Category filter: ${log.category}`
    });
  });

  return logs.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
};

const generateTimeSeriesData = (packets, groupBy = 'hour') => {
  const timeMap = new Map();
  
  packets.forEach(packet => {
    const date = new Date(packet.timestamp);
    let key;
    
    if (groupBy === 'day') {
      key = `${date.getMonth() + 1}/${date.getDate()}`;
    } else {
      key = `${date.getMonth() + 1}/${date.getDate()} ${date.getHours()}:00`;
    }
    
    if (!timeMap.has(key)) {
      timeMap.set(key, { date: key, threats: 0, devices: new Set(), packets: 0 });
    }
    
    const entry = timeMap.get(key);
    entry.packets++;
    entry.devices.add(packet.sourceIP);
    
    // Simple threat detection for time series
    const suspiciousPorts = [22, 23, 135, 139, 445];
    if (suspiciousPorts.includes(packet.destPort) || packet.length > 1400) {
      entry.threats++;
    }
  });

  return Array.from(timeMap.values()).map(entry => ({
    date: entry.date,
    threats: entry.threats,
    devices: entry.devices.size,
    packets: entry.packets
  })).sort();
};

// Analytics API endpoints
app.get('/api/analytics/logs', (req, res) => {
  try {
    const packets = getPackets();
    const logs = generateActivityLogs(packets);
    res.json({ logs, timestamp: new Date().toISOString() });
  } catch (error) {
    res.status(500).json({ error: 'Failed to generate analytics logs' });
  }
});

app.get('/api/analytics/threats-timeline', (req, res) => {
  try {
    const packets = getPackets();
    const timelineData = generateTimeSeriesData(packets, 'day').slice(-7); // Last 7 days
    res.json({ 
      data: timelineData.map(item => ({ date: item.date, threats: item.threats })),
      timestamp: new Date().toISOString() 
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to generate threats timeline' });
  }
});

app.get('/api/analytics/device-activity', (req, res) => {
  try {
    const packets = getPackets();
    const timelineData = generateTimeSeriesData(packets, 'day').slice(-7); // Last 7 days
    res.json({ 
      data: timelineData.map(item => ({ date: item.date, devices: item.devices })),
      timestamp: new Date().toISOString() 
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to generate device activity data' });
  }
});

app.get('/api/analytics/top-devices', (req, res) => {
  try {
    const packets = getPackets();
    const devices = analyzeDeviceActivity(packets);
    const topDevices = devices
      .sort((a, b) => b.packetCount - a.packetCount)
      .slice(0, 5)
      .map(device => ({
        name: device.ip,
        packets: device.packetCount
      }));
    
    res.json({ 
      data: topDevices,
      timestamp: new Date().toISOString() 
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to generate top devices data' });
  }
});

// Dashboard-specific endpoints
const generateDashboardStats = (packets) => {
  const devices = analyzeDeviceActivity(packets);
  const threats = analyzePacketsForThreats(packets);
  const parentalLogs = 3; // Mock parental control blocks
  
  // Calculate network health based on threat ratio and device activity
  const threatRatio = threats.length / Math.max(packets.length, 1);
  const baseHealth = Math.max(60, 100 - (threatRatio * 200));
  const networkHealth = Math.min(100, Math.round(baseHealth + Math.random() * 10));
  
  return {
    totalDevices: devices.length,
    packetsScanned: packets.length,
    threatsBlocked: threats.length,
    parentalBlocks: parentalLogs,
    networkHealth: networkHealth
  };
};

const generateRecentAlerts = (packets) => {
  const alerts = [];
  const threats = analyzePacketsForThreats(packets);
  const devices = analyzeDeviceActivity(packets);
  
  // Add threat alerts
  threats.slice(0, 3).forEach(threat => {
    alerts.push({
      id: threat.id,
      timestamp: threat.timestamp,
      type: 'threat',
      message: threat.message,
      severity: threat.severity
    });
  });
  
  // Add device alerts for new connections
  devices.slice(0, 2).forEach((device, index) => {
    alerts.push({
      id: Date.now() + index + 100,
      timestamp: device.lastSeen,
      type: 'device',
      message: `Device activity: ${device.ip}`,
      severity: 'low'
    });
  });
  
  // Add mock parental control alerts
  alerts.push({
    id: Date.now() + 200,
    timestamp: new Date(Date.now() - Math.random() * 3600000).toISOString(),
    type: 'parental',
    message: 'Blocked gaming site during restricted hours',
    severity: 'medium'
  });
  
  return alerts.slice(0, 5).sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
};

const generateNewDevices = (packets) => {
  const devices = analyzeDeviceActivity(packets);
  const deviceTypes = ['Mobile', 'Computer', 'IoT', 'Smart TV', 'Tablet'];
  
  return devices.slice(0, 3).map((device, index) => ({
    id: index + 1,
    name: `Device-${device.ip.split('.').pop()}`,
    ip: device.ip,
    joinedAt: device.lastSeen,
    type: deviceTypes[index % deviceTypes.length]
  }));
};

const generateTopThreats = (packets) => {
  const threats = analyzePacketsForThreats(packets);
  const threatDomains = [
    'malware.example.com',
    'phishing-site.net', 
    'suspicious-ads.com',
    'botnet.attack.org',
    'spyware.bad.com'
  ];
  
  // Group threats by type and create domain-based threats
  const threatMap = new Map();
  
  threats.forEach(threat => {
    const domain = threatDomains[Math.floor(Math.random() * threatDomains.length)];
    const key = domain;
    
    if (!threatMap.has(key)) {
      threatMap.set(key, {
        id: Date.now() + Math.random(),
        domain: domain,
        ip: threat.sourceIP || threat.destIP || '192.168.1.1',
        severity: threat.severity,
        count: 0
      });
    }
    
    threatMap.get(key).count++;
  });
  
  return Array.from(threatMap.values())
    .sort((a, b) => b.count - a.count)
    .slice(0, 3);
};

const generateThreatActivity = (packets) => {
  const now = new Date();
  const hourlyData = [];
  
  for (let i = 0; i < 7; i++) {
    const hour = Math.max(0, now.getHours() - (6 - i) * 4);
    const timeLabel = `${hour.toString().padStart(2, '0')}:00`;
    
    // Count threats in this time period
    const threats = analyzePacketsForThreats(packets.filter(p => {
      const packetHour = new Date(p.timestamp).getHours();
      return Math.abs(packetHour - hour) <= 1;
    }));
    
    hourlyData.push({
      time: timeLabel,
      threats: threats.length
    });
  }
  
  return hourlyData;
};

app.get('/api/dashboard/stats', (req, res) => {
  try {
    const packets = getPackets();
    const stats = generateDashboardStats(packets);
    res.json({ stats, timestamp: new Date().toISOString() });
  } catch (error) {
    res.status(500).json({ error: 'Failed to generate dashboard stats' });
  }
});

app.get('/api/dashboard/alerts', (req, res) => {
  try {
    const packets = getPackets();
    const alerts = generateRecentAlerts(packets);
    res.json({ alerts, timestamp: new Date().toISOString() });
  } catch (error) {
    res.status(500).json({ error: 'Failed to generate recent alerts' });
  }
});

app.get('/api/dashboard/devices', (req, res) => {
  try {
    const packets = getPackets();
    const devices = generateNewDevices(packets);
    res.json({ devices, timestamp: new Date().toISOString() });
  } catch (error) {
    res.status(500).json({ error: 'Failed to generate new devices data' });
  }
});

app.get('/api/dashboard/threats', (req, res) => {
  try {
    const packets = getPackets();
    const threats = generateTopThreats(packets);
    res.json({ threats, timestamp: new Date().toISOString() });
  } catch (error) {
    res.status(500).json({ error: 'Failed to generate top threats data' });
  }
});

app.get('/api/dashboard/activity', (req, res) => {
  try {
    const packets = getPackets();
    const activity = generateThreatActivity(packets);
    res.json({ activity, timestamp: new Date().toISOString() });
  } catch (error) {
    res.status(500).json({ error: 'Failed to generate threat activity data' });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Endpoint not found' });
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Health check: http://localhost:${PORT}/api/health`);
  console.log(`Packets API: http://localhost:${PORT}/api/packets`);
});
