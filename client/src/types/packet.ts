export interface PacketData {
  id: number;
  timestamp: string;
  protocol: string;
  sourceIP: string;
  destIP: string;
  sourcePort: number;
  destPort: number;
  length: number;
  flags?: string | null;
  payload: string;
}

export interface PacketResponse {
  packets: PacketData[];
  total: number;
  timestamp: string;
}

export interface StatsData {
  totalPackets: number;
  protocolDistribution: { [key: string]: number };
  averagePacketSize: number;
  timeRange: {
    earliest?: string;
    latest?: string;
  };
}

export interface ApiFilters {
  limit?: number;
  protocol?: string;
  sourceIP?: string;
  destIP?: string;
}