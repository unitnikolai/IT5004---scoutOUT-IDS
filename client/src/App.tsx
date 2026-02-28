import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import Layout from './components/Layout';
import Dashboard from './pages/Dashboard';
import NetworkTraffic from './pages/NetworkTraffic';
import ParentalControls from './pages/ParentalControls';
import Analytics from './pages/Analytics';
import Threats from './pages/Threats';
import Devices from './pages/Devices';
import Settings from './pages/Settings';
import Help from './pages/Help';
import './App.css';

function App() {
  return (
    <Router>
      <Layout>
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/traffic" element={<NetworkTraffic />} />
          <Route path="/parental-controls" element={<ParentalControls />} />
          <Route path="/analytics" element={<Analytics />} />
          <Route path="/threats" element={<Threats />} />
          <Route path="/devices" element={<Devices />} />
          <Route path="/settings" element={<Settings />} />
          <Route path="/help" element={<Help />} />
        </Routes>
      </Layout>
    </Router>
  );
}

export default App;
