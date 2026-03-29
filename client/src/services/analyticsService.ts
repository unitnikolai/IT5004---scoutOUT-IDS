import axios from 'axios';

const getApiUrl = (): string => {
  // Use environment variable if set (Docker production)
  if (process.env.REACT_APP_API_URL) {
    return process.env.REACT_APP_API_URL;
  }
  
  // Otherwise, dynamically detect based on frontend URL
  const protocol = window.location.protocol; // http: or https:
  const hostname = window.location.hostname; // localhost, 192.168.x.x, etc.
  const port = ':5050'; // Backend API port
  const path = '/api';
  
  return `${protocol}//${hostname}${port}${path}`;
};

const API_BASE_URL = getApiUrl()

const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 10000,
});

export interface LogEntry {
  id: number;
  timestamp: string;
  type: 'threat' | 'device' | 'parental';
  message: string;
  details: string;
}

export interface TimeSeriesData {
  date: string;
  threats?: number;
  devices?: number;
  packets?: number;
}

export interface TopDevice {
  name: string;
  packets: number;
}

export interface AnalyticsResponse<T> {
  data?: T;
  logs?: LogEntry[];
  timestamp: string;
}

export const analyticsService = {
  // Get activity logs
  async getLogs(): Promise<AnalyticsResponse<LogEntry[]>> {
    const response = await api.get('/analytics/logs');
    return response.data;
  },

  // Get threats timeline data
  async getThreatsTimeline(): Promise<AnalyticsResponse<TimeSeriesData[]>> {
    const response = await api.get('/analytics/threats-timeline');
    return response.data;
  },

  // Get device activity timeline data
  async getDeviceActivity(): Promise<AnalyticsResponse<TimeSeriesData[]>> {
    const response = await api.get('/analytics/device-activity');
    return response.data;
  },

  // Get top devices data
  async getTopDevices(): Promise<AnalyticsResponse<TopDevice[]>> {
    const response = await api.get('/analytics/top-devices');
    return response.data;
  },
};

export default analyticsService;