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

export const packetService = {
  // Get health status
  async getHealth(): Promise<{ status: string; timestamp: string }> {
    const response = await api.get('/health');
    return response.data;
  },

  // Get packets with optional filters
  async getPackets(filters: ApiFilters = {}): Promise<PacketResponse> {
    const params = new URLSearchParams();
    
    if (filters.limit) params.append('limit', filters.limit.toString());
    if (filters.protocol) params.append('protocol', filters.protocol);
    if (filters.sourceIP) params.append('sourceIP', filters.sourceIP);
    if (filters.destIP) params.append('destIP', filters.destIP);
    
    const response = await api.get(`/packets?${params.toString()}`);
    return response.data;
  },

  // Get single packet by ID
  async getPacketById(id: number): Promise<PacketData> {
    const response = await api.get(`/packets/${id}`);
    return response.data;
  },

  // Get statistics
  async getStats(): Promise<StatsData> {
    const response = await api.get('/stats');
    return response.data;
  },
};

export default packetService;