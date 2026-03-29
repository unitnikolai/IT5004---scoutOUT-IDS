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
  timeout: 15000, // Increased timeout to handle backend processing delays
});

// Request cancellation
let abortController = new AbortController();

// Detect abort errors including DNS cancellations (ns binding)
const isAbortError = (error: any): boolean => {
  const message = error?.message?.toLowerCase() || '';
  return (
    error?.code === 'ECONNABORTED' ||
    error?.code === 'ERR_CANCELED' ||
    error?.name === 'AbortError' ||
    message.includes('abort') ||
    message.includes('cancel') ||
    message.includes('ns binding')
  );
};

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
  // Cancel all pending requests
  cancelRequests(): void {
    abortController.abort();
    abortController = new AbortController();
  },

  // Get activity logs
  async getLogs(): Promise<AnalyticsResponse<LogEntry[]>> {
    try {
      const response = await api.get('/analytics/logs', {
        signal: abortController.signal
      });
      return response.data;
    } catch (error: any) {
      if (isAbortError(error)) {
        throw error; // Re-throw abort errors without logging
      }
      console.error('Error fetching logs:', error);
      throw error;
    }
  },

  // Get threats timeline data
  async getThreatsTimeline(): Promise<AnalyticsResponse<TimeSeriesData[]>> {
    try {
      const response = await api.get('/analytics/threats-timeline', {
        signal: abortController.signal
      });
      return response.data;
    } catch (error: any) {
      if (isAbortError(error)) {
        throw error; // Re-throw abort errors without logging
      }
      console.error('Error fetching threats timeline:', error);
      throw error;
    }
  },

  // Get device activity timeline data
  async getDeviceActivity(): Promise<AnalyticsResponse<TimeSeriesData[]>> {
    try {
      const response = await api.get('/analytics/device-activity', {
        signal: abortController.signal
      });
      return response.data;
    } catch (error: any) {
      if (isAbortError(error)) {
        throw error; // Re-throw abort errors without logging
      }
      console.error('Error fetching device activity:', error);
      throw error;
    }
  },

  // Get top devices data
  async getTopDevices(): Promise<AnalyticsResponse<TopDevice[]>> {
    try {
      const response = await api.get('/analytics/top-devices', {
        signal: abortController.signal
      });
      return response.data;
    } catch (error: any) {
      if (isAbortError(error)) {
        throw error; // Re-throw abort errors without logging
      }
      console.error('Error fetching top devices:', error);
      throw error;
    }
  },
};

export default analyticsService;