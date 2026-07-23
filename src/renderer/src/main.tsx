import React from 'react';
import ReactDOM from 'react-dom/client';
import { App } from './App';
import './styles.css';
import './bluetoothAnalytics.css';
import './bluetoothWorkspace.css';
import './bluetoothMap.css';
import './bluetoothRelations.css';
import './bluetoothDevices.css';
import './wifiReportsAnalytics.css';
import './radioTimeline.css';
import './radioEvidence.css';
import './radioPresence.css';

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
