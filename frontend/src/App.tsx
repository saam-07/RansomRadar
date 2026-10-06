import { useState, useEffect, useCallback } from 'react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { Navbar } from './components/layout/Navbar';
import { Sidebar, NavTab } from './components/layout/Sidebar';
import { DashboardPage } from './pages/DashboardPage';
import { ScenarioRunnerPage } from './pages/ScenarioRunnerPage';
import { DetectorComparisonPage } from './pages/DetectorComparisonPage';
import { DatasetsPage } from './pages/DatasetsPage';
import { ModelsPage } from './pages/ModelsPage';
import { AlertsPage } from './pages/AlertsPage';
import { SettingsPage } from './pages/SettingsPage';
import { GuidedDemoModal } from './components/demo/GuidedDemoModal';
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
  const [isGuidedDemoOpen, setIsGuidedDemoOpen] = useState<boolean>(false);

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
        onOpenGuidedDemo={() => setIsGuidedDemoOpen(true)}
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
            <ScenarioRunnerPage
              wsEvents={wsEvents}
              onRefreshStatus={fetchStatus}
            />
          )}

          {currentTab === 'comparison' && (
            <DetectorComparisonPage />
          )}

          {currentTab === 'datasets' && (
            <DatasetsPage />
          )}

          {currentTab === 'models' && (
            <ModelsPage />
          )}

          {currentTab === 'alerts' && (
            <AlertsPage />
          )}

          {currentTab === 'settings' && (
            <SettingsPage />
          )}
        </main>
      </div>

      {/* 3-Minute Guided Demo Story Mode Modal */}
      <GuidedDemoModal
        isOpen={isGuidedDemoOpen}
        onClose={() => setIsGuidedDemoOpen(false)}
        onNavigate={(page) => {
          if (['dashboard', 'scenarios', 'comparison', 'datasets', 'models', 'alerts', 'settings'].includes(page)) {
            setCurrentTab(page as NavTab);
          }
        }}
      />
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
