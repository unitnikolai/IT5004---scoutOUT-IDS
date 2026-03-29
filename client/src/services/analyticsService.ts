import axios from 'axios';

const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:5050/api' || 'http://172.20.0.31:5050/api';

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