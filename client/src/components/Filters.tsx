import React, { useState } from 'react';
import { ApiFilters } from '../types/packet';
import './Filters.css';

interface FiltersProps {
  onFiltersChange: (filters: ApiFilters) => void;
  isLoading?: boolean;
}

const Filters: React.FC<FiltersProps> = ({ onFiltersChange, isLoading }) => {
  const [filters, setFilters] = useState<ApiFilters>({
    limit: 50,
    protocol: '',
    sourceIP: '',
    destIP: ''
  });

  const handleFilterChange = (key: keyof ApiFilters, value: string | number) => {
    const newFilters = { ...filters, [key]: value };
    setFilters(newFilters);
    onFiltersChange(newFilters);
  };

  const handleReset = () => {
    const resetFilters: ApiFilters = {
      limit: 50,
      protocol: '',
      sourceIP: '',
      destIP: ''
    };
    setFilters(resetFilters);
    onFiltersChange(resetFilters);
  };

  return (
    <div className="filters-container">
      <h3>Filters</h3>
      
      <div className="filters-grid">
        <div className="filter-group">
          <label htmlFor="limit">Limit:</label>
          <select
            id="limit"
            value={filters.limit || 50}
            onChange={(e) => handleFilterChange('limit', parseInt(e.target.value))}
            disabled={isLoading}
          >
            <option value={10}>10</option>
            <option value={25}>25</option>
            <option value={50}>50</option>
            <option value={100}>100</option>
            <option value={500}>500</option>
          </select>
        </div>

        <div className="filter-group">
          <label htmlFor="protocol">Protocol:</label>
          <select
            id="protocol"
            value={filters.protocol || ''}
            onChange={(e) => handleFilterChange('protocol', e.target.value)}
            disabled={isLoading}
          >
            <option value="">All Protocols</option>
            <option value="TCP">TCP</option>
            <option value="UDP">UDP</option>
            <option value="HTTP">HTTP</option>
            <option value="HTTPS">HTTPS</option>
            <option value="ICMP">ICMP</option>
            <option value="FTP">FTP</option>
            <option value="SSH">SSH</option>
          </select>
        </div>

        <div className="filter-group">
          <label htmlFor="sourceIP">Source IP:</label>
          <input
            id="sourceIP"
            type="text"
            placeholder="e.g., 192.168.1.100"
            value={filters.sourceIP || ''}
            onChange={(e) => handleFilterChange('sourceIP', e.target.value)}
            disabled={isLoading}
          />
        </div>

        <div className="filter-group">
          <label htmlFor="destIP">Destination IP:</label>
          <input
            id="destIP"
            type="text"
            placeholder="e.g., 8.8.8.8"
            value={filters.destIP || ''}
            onChange={(e) => handleFilterChange('destIP', e.target.value)}
            disabled={isLoading}
          />
        </div>

        <div className="filter-actions">
          <button 
            onClick={handleReset}
            disabled={isLoading}
            className="reset-button"
          >
            Reset Filters
          </button>
        </div>
      </div>
    </div>
  );
};

export default Filters;