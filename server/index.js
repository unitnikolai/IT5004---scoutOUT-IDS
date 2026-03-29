const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const { addPacket, getPackets } = require('./packetStore.js');
const { isPrivateIP, checkPublicIP } = require('./virustotal.js');
const app = express();
const PORT = process.env.PORT || 5050;
// Middleware
app.use(cors());
app.use(express.json());

require('dotenv').config();

const VT_API_KEY = process.env.VIRUSTOTAL_API_KEY;
const vtCache = new Map(); 


const CACHE_TTL = 60 * 60 * 1000; // 1 hour
// Rate limiting - separate limiters for different endpoints

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 1000 // limit each IP to 1000 requests per windowMs
});

const batchLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 500 // higher limit for batch operations (each batch can contain many packets)
});

app.use('/api/', limiter);

app.get('/api/health', (req, res) => {
  res.json({ status: 'OK', timestamp: new Date().toISOString() });
});



// Batch packets endpoint - efficient for high-volume packet streams
app.post('/api/packets/', batchLimiter, (req, res) => {
  const packets = Array.isArray(req.body) ? req.body : [req.body];
  
  let added = 0;
  packets.forEach(packet => {
    if (packet && packet.timestamp) {
      addPacket(packet);
      added++;
    }
  });
    console.log(`[Batch Receiver] Added ${added}/${packets.length} packets. Total in store: ${require('./packetStore.js').getPackets().length}`);
    res.status(201).json({ 
    status: 'ok',
    packetsAdded: added,
    totalRequested: packets.length
  });
});

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
  const threats = [];

  packets.forEach(packet => {
    // Skip packets without required fields
    if (!packet.sourceIP || !packet.timestamp) return;
    
    let threatType = '';
    let severity = 'low';
    let message = '';

    // Check for suspicious ports
    if (packet.destPort && suspiciousPorts.includes(packet.destPort)) {
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
      p.timestamp &&
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
        destIP: packet.destIP || 'unknown',
        severity
      });
    }
  });

  return threats;
};

const analyzeDeviceActivity = (packets) => {
  const deviceMap = new Map();
  
  packets.forEach(packet => {
    // Skip packets without required sourceIP
    if (!packet.sourceIP) return;
    
    const deviceKey = packet.sourceIP;
    if (!deviceMap.has(deviceKey)) {
      deviceMap.set(deviceKey, {
        ip: packet.sourceIP,
        lastSeen: packet.timestamp || new Date().toISOString(),
        packetCount: 0,
        protocols: new Set(),
        totalBytes: 0
      });
    }
    
    const device = deviceMap.get(deviceKey);
    device.packetCount++;
    device.totalBytes += packet.length || 0;
    if (packet.protocol) device.protocols.add(packet.protocol);
    
    if (packet.timestamp && new Date(packet.timestamp) > new Date(device.lastSeen)) {
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

// VirusTotal API endpoint for threat detection
app.get('/api/virustotal/ip/:ip', async (req, res) => {
  try {
    const { ip } = req.params;
    
    // Validate IP format
    if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) {
      return res.status(400).json({ error: 'Invalid IP format' });
    }
    
    const report = await checkPublicIP(ip);  
    res.json(report);
  } catch (error) {
    console.error('VirusTotal check error:', error);
    res.status(500).json({ error: 'Failed to check IP against VirusTotal' });
  }
});

// Enhanced threat detection with VirusTotal checks
app.get('/api/threats/enhanced', async (req, res) => {
  try {
    const packets = getPackets();
    const threats = [];
    const checkedIPs = new Set();

    // First get threats from packet analysis
    const basicThreats = analyzePacketsForThreats(packets);
    threats.push(...basicThreats);

    // Then check suspicious IPs against VirusTotal
    const suspiciousIPs = new Set();
    packets.forEach(packet => {
      // Collect IPs from suspicious connections
      if ([22, 23, 135, 139, 445, 1433, 3389].includes(packet.destPort)) {
        suspiciousIPs.add(packet.destIP);
      }
    });

    // Check each suspicious IP with VirusTotal (limit to avoid API rate limits)
    const ipsToCheck = Array.from(suspiciousIPs).slice(0, 5);
    for (const ip of ipsToCheck) {
      if (!isPrivateIP(ip) && !checkedIPs.has(ip)) {
        checkedIPs.add(ip);
        try {
          const vtReport = await checkPublicIP(ip);
          if (vtReport && vtReport.stats && (vtReport.stats.malicious > 0 || vtReport.stats.suspicious > 0)) {
            threats.push({
              id: Date.now() + Math.random(),
              timestamp: new Date().toISOString(),
              type: 'virustotal',
              message: `VirusTotal detection: IP ${ip} flagged (${vtReport.stats.malicious} malicious, ${vtReport.stats.suspicious} suspicious)`,
              details: `VirusTotal report: ${vtReport.stats.malicious} malicious, ${vtReport.stats.suspicious} suspicious detections`,
              sourceIP: ip,
              destIP: ip,
              severity: vtReport.stats.malicious > 0 ? 'critical' : 'high'
            });
          }
        } catch (e) {
          console.debug(`Failed to check IP ${ip} with VirusTotal:`, e.message);
        }
      }
    }

    res.json({ 
      threats,
      totalThreats: threats.length,
      timestamp: new Date().toISOString() 
    });
  } catch (error) {
    console.error('Enhanced threat analysis error:', error);
    res.status(500).json({ error: 'Failed to analyze threats' });
  }
});

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

// Devices API endpoint - Extract real devices from packet data with hostname resolution
app.get('/api/devices/all', (req, res) => {
  try {
    const packets = getPackets();
    const devices = analyzeDeviceActivity(packets);
    
    // Build hostname map from packets
    const hostnameMap = new Map();
    packets.forEach(packet => {
      if (packet.sourceIP && packet.hostname) {
        if (!hostnameMap.has(packet.sourceIP)) {
          hostnameMap.set(packet.sourceIP, packet.hostname);
        }
      }
    });

    // Convert to full device objects
    const fullDevices = devices.map((device, index) => {
      const hostname = hostnameMap.get(device.ip) || `Device-${device.ip.split('.').pop()}`;
      const deviceTypes = ['Mobile', 'Computer', 'IoT', 'Smart TV', 'Tablet', 'Unknown'];
      
      // Simple device type detection based on port usage
      let type = 'Unknown';
      const portSet = new Set();
      packets.forEach(p => {
        if (p.sourceIP === device.ip) {
          portSet.add(p.sourcePort);
        }
      });
      
      if (portSet.has(5353) || portSet.has(68)) type = 'IoT'; // mDNS or DHCP
      else if (portSet.has(22) || portSet.has(3389)) type = 'Computer'; // SSH or RDP
      else if (device.packetCount > 1000) type = 'Computer';
      else if (device.packetCount < 50) type = 'IoT';
      else type = deviceTypes[Math.floor(Math.random() * deviceTypes.length)];

      return {
        id: index + 1,
        name: hostname,
        ip: device.ip,
        mac: `${device.ip.split('.').slice(2).join('-')}:${(Math.random() * 256 | 0).toString(16)}`, // Simulated MAC
        vendor: 'Network Device',
        type: type,
        firstSeen: device.lastSeen, // Using lastSeen as approximation; could track first packet per IP
        lastSeen: device.lastSeen,
        trust: 'trusted',
        assignedTo: 'Guest',
        bandwidth: Math.round((device.totalBytes / 1024 / 1024) / 10) // Convert bytes to Mbps estimate
      };
    });

    res.json({ 
      devices: fullDevices,
      total: fullDevices.length,
      timestamp: new Date().toISOString() 
    });
  } catch (error) {
    console.error('Failed to fetch devices:', error);
    res.status(500).json({ error: 'Failed to fetch devices' });
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
  
  return devices
    .filter(device => device && device.ip) // Filter out invalid devices
    .slice(0, 3)
    .map((device, index) => ({
      id: index + 1,
      name: `Device-${device.ip.split('.').pop() || 'unknown'}`,
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
    console.log(`[Dashboard Stats] Fetched ${packets.length} packets`);
    if (packets.length > 0) {
      console.log(`[Dashboard Stats] Sample packet:`, JSON.stringify(packets[0], null, 2).substring(0, 200));
    }
    const stats = generateDashboardStats(packets);
    console.log(`[Dashboard Stats] Returning:`, JSON.stringify({stats, timestamp: new Date().toISOString()}).substring(0, 300));
    res.json({ stats, timestamp: new Date().toISOString() });
  } catch (error) {
    console.error('[Dashboard Stats] Error:', error);
    res.status(500).json({ error: 'Failed to generate dashboard stats' });
  }
});

app.get('/api/dashboard/alerts', (req, res) => {
  try {
    const packets = getPackets();
    const alerts = generateRecentAlerts(packets);
    console.log(`[Dashboard Alerts] Returning ${alerts.length} alerts`);
    res.json({ alerts, timestamp: new Date().toISOString() });
  } catch (error) {
    res.status(500).json({ error: 'Failed to generate recent alerts' });
  }
});

app.get('/api/dashboard/devices', (req, res) => {
  try {
    const packets = getPackets();
    const devices = generateNewDevices(packets);
    console.log(`[Dashboard Devices] Returning ${devices.length} devices`);
    res.json({ devices, timestamp: new Date().toISOString() });
  } catch (error) {
    res.status(500).json({ error: 'Failed to generate new devices data' });
  }
});

app.get('/api/dashboard/threats', (req, res) => {
  try {
    const packets = getPackets();
    const threats = generateTopThreats(packets);
    console.log(`[Dashboard Threats] Returning ${threats.length} threats`);
    res.json({ threats, timestamp: new Date().toISOString() });
  } catch (error) {
    res.status(500).json({ error: 'Failed to generate top threats data' });
  }
});

app.get('/api/dashboard/activity', (req, res) => {
  try {
    const packets = getPackets();
    const activity = generateThreatActivity(packets);
    console.log(`[Dashboard Activity] Returning ${activity.length} activity entries`);
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

app.listen(PORT, '0.0.0.0',() => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Health check: http://localhost:${PORT}/api/health`);
  console.log(`Packets API: http://localhost:${PORT}/api/packets`);
});
