import axios from 'axios';
import { PacketData, PacketResponse, StatsData, ApiFilters } from '../types/packet';


const getApiUrl = (): string => {
  // Use environment variable if set (Docker production)
  if (process.env.REACT_APP_API_URL) {
    return process.env.REACT_APP_API_URL;
  }
  
  const protocol = window.location.protocol; // http: or https:
  const hostname = window.location.hostname; // localhost, 192.168.x.x, etc.
  const port = ':5050'; // Backend API port
  const path = '/api';
  
  return `${protocol}//${hostname}${port}${path}`;
};

const API_BASE_URL = process.env.REACT_APP_API_URL || getApiUrl();

const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 10000,
});

// Request cancellation
let abortController = new AbortController();

const isAbortError = (error: any): boolean => {
  return (
    error?.code === 'ECONNABORTED' ||
    error?.name === 'AbortError' ||
    error?.message?.includes('cancel')
  );
};

export const packetService = {
  // Cancel all pending requests
  cancelRequests(): void {
    abortController.abort();
    abortController = new AbortController();
  },

  // Get health status
  async getHealth(): Promise<{ status: string; timestamp: string }> {
    try {
      const response = await api.get('/health', {
        signal: abortController.signal
      });
      return response.data;
    } catch (error: any) {
      if (isAbortError(error)) {
        throw error; // Re-throw abort errors without logging
      }
      console.error('Error checking health:', error);
      throw error;
    }
  },

  // Get packets with optional filters
  async getPackets(filters: ApiFilters = {}): Promise<PacketResponse> {
    try {
      const params = new URLSearchParams();
      
      if (filters.limit) params.append('limit', filters.limit.toString());
      if (filters.protocol) params.append('protocol', filters.protocol);
      if (filters.sourceIP) params.append('sourceIP', filters.sourceIP);
      if (filters.destIP) params.append('destIP', filters.destIP);
      
      const response = await api.get(`/packets?${params.toString()}`, {
        signal: abortController.signal
      });
      return response.data;
    } catch (error: any) {
      if (isAbortError(error)) {
        throw error; // Re-throw abort errors without logging
      }
      console.error('Error fetching packets:', error);
      throw error;
    }
  },

  // Get single packet by ID
  async getPacketById(id: number): Promise<PacketData> {
    try {
      const response = await api.get(`/packets/${id}`, {
        signal: abortController.signal
      });
      return response.data;
    } catch (error: any) {
      if (isAbortError(error)) {
        throw error; // Re-throw abort errors without logging
      }
      console.error('Error fetching packet:', error);
      throw error;
    }
  },

  // Get statistics
  async getStats(): Promise<StatsData> {
    try {
      const response = await api.get('/stats', {
        signal: abortController.signal
      });
      return response.data;
    } catch (error: any) {
      if (isAbortError(error)) {
        throw error; // Re-throw abort errors without logging
      }
      console.error('Error fetching stats:', error);
      throw error;
    }
  },
};

export default packetService;