import { useState, useEffect, useCallback } from 'react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { Navbar } from './components/layout/Navbar';
import { Sidebar, NavTab } from './components/layout/Sidebar';
import { DashboardPage } from './pages/DashboardPage';
import { StubPage } from './pages/StubPage';
import { api } from './api/client';
import { SystemStatus, WebSocketEvent } from './types/api';
import { useWebSocket } from './hooks/useWebSocket';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      refetchOnWindowFocus: false,
      retry: 1,
    },
  },
});

export function AppContent() {
  const [currentTab, setCurrentTab] = useState<NavTab>('dashboard');
  const [status, setStatus] = useState<SystemStatus | null>(null);
  const [wsEvents, setWsEvents] = useState<WebSocketEvent[]>([]);

  // Fetch system status
  const fetchStatus = useCallback(async () => {
    try {
      const data = await api.getStatus();
      setStatus(data);
    } catch (e) {
      console.error('Failed to fetch status:', e);
    }
  }, []);

  useEffect(() => {
    fetchStatus();
    const interval = setInterval(fetchStatus, 5000);
    return () => clearInterval(interval);
  }, [fetchStatus]);

  // WebSocket hook with batched events handler
  const { isConnected } = useWebSocket({
    onEvents: (events) => {
      setWsEvents(events);
    },
  });

  const handlePolicyChange = async (newPolicy: string) => {
    try {
      await api.setControl({ policy: newPolicy });
      fetchStatus();
    } catch (e: any) {
      alert(`Policy change failed: ${e.message}`);
    }
  };

  const handleResetStorm = async () => {
    try {
      await api.setControl({ reset_storm: true });
      fetchStatus();
    } catch (e: any) {
      alert(`Reset panic failed: ${e.message}`);
    }
  };

  return (
    <div className="flex flex-col h-screen bg-[#080d1a] text-slate-100 overflow-hidden">
      {/* Persistent Top Navigation Bar */}
      <Navbar
        status={status}
        wsConnected={isConnected}
        onPolicyChange={handlePolicyChange}
        onResetStorm={handleResetStorm}
      />

      <div className="flex flex-1 overflow-hidden">
        {/* Left Sidebar */}
        <Sidebar currentTab={currentTab} onSelectTab={setCurrentTab} />

        {/* Main Content Area */}
        <main className="flex-1 flex flex-col overflow-hidden bg-[#0a1020]">
          {currentTab === 'dashboard' && (
            <DashboardPage
              status={status}
              wsEvents={wsEvents}
              onRefreshStatus={fetchStatus}
            />
          )}

          {currentTab === 'scenarios' && (
            <StubPage
              title="Scenario Runner & Restoration Visualizer"
              promptStage="Prompt 7"
              description="Dedicated scenario cards, live filesystem grid showing file-by-file encryption and rollback restoration, and speed controls."
            />
          )}

          {currentTab === 'comparison' && (
            <StubPage
              title="Detector Comparison Benchmark"
              promptStage="Prompt 7"
              description="Side-by-side detection performance comparison: Rule-based heuristics vs Random Forest vs XGBoost with ROC/PR curves and latency."
            />
          )}

          {currentTab === 'datasets' && (
            <StubPage
              title="Benchmark Datasets Explorer"
              promptStage="Prompt 8"
              description="Interactive feature distributions, class overlap histograms, raw trace samples, and dataset generation tool."
            />
          )}

          {currentTab === 'models' && (
            <StubPage
              title="Model Registry & Training Studio"
              promptStage="Prompt 8"
              description="Active model registry, background training job dispatch, evaluation curves, and interactive 11-feature 'Try It' prediction widget."
            />
          )}

          {currentTab === 'alerts' && (
            <StubPage
              title="Forensics & Investigation Hub"
              promptStage="Prompt 9"
              description="Comprehensive historical alert records, forensic tree feature contribution graphs, and incident containment logs."
            />
          )}

          {currentTab === 'settings' && (
            <StubPage
              title="Engine Configuration & Safety Controls"
              promptStage="Prompt 9"
              description="Tune EWMA alpha smoothing, risk thresholds (0.3/0.6/0.85), process allowlists, and false-positive storm parameters."
            />
          )}
        </main>
      </div>
    </div>
  );
}

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <AppContent />
    </QueryClientProvider>
  );
}
