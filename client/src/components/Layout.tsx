import React from 'react';
import { NavLink } from 'react-router-dom';
import { 
  FiHome, 
  FiActivity, 
  FiShield, 
  FiBarChart2, 
  FiAlertTriangle, 
  FiMonitor, 
  FiSettings, 
  FiHelpCircle 
} from 'react-icons/fi';
import './Layout.css';

interface LayoutProps {
  children: React.ReactNode;
}

const Layout: React.FC<LayoutProps> = ({ children }) => {
  return (
    <div className="layout">
      <nav className="sidebar">
        <div className="sidebar-header">
          <img src ="/scoutout.png" alt="ScoutOut Logo" className="logo" />
          <h1>ScoutOut</h1>
        </div>
        
        <div className="sidebar-menu">
          <NavLink to="/" className={({ isActive }) => isActive ? 'menu-item active' : 'menu-item'} end>
            <FiHome size={20} />
            <span>Dashboard</span>
          </NavLink>
          
          <NavLink to="/traffic" className={({ isActive }) => isActive ? 'menu-item active' : 'menu-item'}>
            <FiActivity size={20} />
            <span>Network Traffic</span>
          </NavLink>
          
          <NavLink to="/parental-controls" className={({ isActive }) => isActive ? 'menu-item active' : 'menu-item'}>
            <FiShield size={20} />
            <span>Parental Controls</span>
          </NavLink>
          
          <NavLink to="/analytics" className={({ isActive }) => isActive ? 'menu-item active' : 'menu-item'}>
            <FiBarChart2 size={20} />
            <span>Analytics</span>
          </NavLink>
          
          <NavLink to="/threats" className={({ isActive }) => isActive ? 'menu-item active' : 'menu-item'}>
            <FiAlertTriangle size={20} />
            <span>Threats</span>
          </NavLink>
          
          <NavLink to="/devices" className={({ isActive }) => isActive ? 'menu-item active' : 'menu-item'}>
            <FiMonitor size={20} />
            <span>Devices</span>
          </NavLink>
          
          <NavLink to="/settings" className={({ isActive }) => isActive ? 'menu-item active' : 'menu-item'}>
            <FiSettings size={20} />
            <span>Settings</span>
          </NavLink>
          
          <NavLink to="/help" className={({ isActive }) => isActive ? 'menu-item active' : 'menu-item'}>
            <FiHelpCircle size={20} />
            <span>Help</span>
          </NavLink>
        </div>
      </nav>
      
      <main className="main-content">
        {children}
      </main>
    </div>
  );
};

export default Layout;
