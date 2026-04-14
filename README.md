# ScoutOut - Packet Capture Viewer

Scout OUT is a plug and play home cybersecurity system that helps families easily monitor and protect their Wi Fi networks and IoT devices through simple, real time alerts and controls.

## Features

- **Real-time Packet Viewing**: Display packet capture data in an easy-to-read table format
- **Advanced Filtering**: Filter packets by protocol, source IP, destination IP, and packet count
- **Network Statistics**: View comprehensive statistics including protocol distribution and average packet size
- **Packet Details**: Click on any packet to view detailed information in a modal
- **Responsive Design**: Works on desktop and mobile devices
- **Connection Status**: Real-time API connection status indicator

## Technology Stack

- **Frontend**: Next.js
- **Backend**: Generic API server, VirusTotal
- **Supporting Components**: Python sensor using Scapy, captures packets and Sends JSON data to the API.

## Quick Start

### Prerequisites

- Node.js (v14 or higher)
- npm

### Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd IT5004---scoutOUT-IDS
```

2. Install dependencies for both backend and frontend:
```bash
npm run install-deps
```

### Running the Application

1. Start both backend and frontend in development mode:
```bash
npm run dev
```

Or run them separately:

2. Start the backend API server:
```bash
npm run server
```

3. In a new terminal, start the frontend:
```bash
npm run client
```

### Accessing the Application

- Frontend: http://localhost:3000
- Backend API: http://localhost:5000

## Components

- **PacketTable**: Displays packets in a sortable table
- **Stats**: Shows network statistics and protocol distribution
- **Filters**: Provides filtering controls
- **PacketDetail**: Modal for viewing detailed packet information

### Main Features

- **Dashboard**: Network security overview with device stats and threat activity
- **Network Traffic**: Real-time packet analysis with protocol distribution
- **Devices**: Device inventory with trust levels and bandwidth monitoring
- **Threats**: Security threat analysis with VirusTotal integration
- **Analytics**: Historical logs and trends visualization
- **Parental Controls**: Website blocking and time-based restrictions
- **Settings**: System configuration and integrations
- **Help**: Interactive tutorials and documentation
