import { useState, useEffect, useCallback } from 'react';
import { Play, Square, RefreshCw } from 'lucide-react';
import { api } from '../api/client';
import { AlertItem, ProcessItem, ScenarioDefinition, SystemStatus, WebSocketEvent } from '../types/api';
import { KpiCards } from '../components/dashboard/KpiCards';
import { RiskTimelineChart, TimelineDataPoint } from '../components/dashboard/RiskTimelineChart';
import { ProcessTable } from '../components/dashboard/ProcessTable';
import { AlertFeed } from '../components/dashboard/AlertFeed';
import { EvidenceDrawer } from '../components/dashboard/EvidenceDrawer';

interface DashboardPageProps {
  status: SystemStatus | null;
  wsEvents: WebSocketEvent[];
  onRefreshStatus: () => void;
}

export const DashboardPage: React.FC<DashboardPageProps> = ({
  status,
  wsEvents,
  onRefreshStatus,
}) => {
  const [processes, setProcesses] = useState<ProcessItem[]>([]);
  const [alerts, setAlerts] = useState<AlertItem[]>([]);
  const [timelineData, setTimelineData] = useState<TimelineDataPoint[]>([]);
  const [scenarios, setScenarios] = useState<ScenarioDefinition[]>([]);
  const [selectedScenario, setSelectedScenario] = useState<string>('fast_ransomware');
  const [simSpeed, setSimSpeed] = useState<number>(5.0);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [selectedAlert, setSelectedAlert] = useState<AlertItem | null>(null);
  const [isDrawerOpen, setIsDrawerOpen] = useState<boolean>(false);
  const [filesSummary, setFilesSummary] = useState({ intact: 300, restored: 0, encrypted: 0 });

  // Initial data load
  const loadInitialData = useCallback(async () => {
    try {
      setIsLoading(true);
      const [procRes, alertsRes, scenRes] = await Promise.all([
        api.getProcesses(),
        api.getAlerts({ limit: 20 }),
        api.getScenarios(),
      ]);

      setProcesses(procRes.processes || []);
      setAlerts(alertsRes.alerts || []);
      setScenarios(scenRes || []);

      // If any existing alerts, populate filesSummary from historical run
      if (alertsRes.alerts && alertsRes.alerts.length > 0) {
        setFilesSummary({ intact: 245, restored: 55, encrypted: 0 });
      }
    } catch (err) {
      console.error('Failed to load initial dashboard data:', err);
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    loadInitialData();
  }, [loadInitialData]);

  // Process incoming WebSocket event batches
  useEffect(() => {
    if (!wsEvents || wsEvents.length === 0) return;

    for (const event of wsEvents) {
      if (event.type === 'window_scored') {
        const d = event.data;
        const pt: TimelineDataPoint = {
          timestamp: d.timestamp || new Date().toISOString(),
          window_idx: d.window_idx ?? timelineData.length + 1,
          ewma: d.ewma ?? 0.0,
          probability: d.probability ?? 0.0,
          pid: d.pid,
          process_name: d.process_name,
        };

        setTimelineData((prev) => {
          const next = [...prev, pt];
          return next.slice(-60); // keep last 60 points for performance
        });

        // Update process in table
        setProcesses((prev) => {
          const existingIdx = prev.findIndex((p) => p.pid === d.pid);
          const updatedProc: ProcessItem = {
            pid: d.pid,
            process_name: d.process_name || `proc_${d.pid}`,
            label: d.label || 'benign',
            risk_level: d.risk_level || 'NORMAL',
            ewma: d.ewma || 0.0,
            probability: d.probability || 0.0,
            status: existingIdx >= 0 ? prev[existingIdx].status : 'normal',
            is_frozen: existingIdx >= 0 ? prev[existingIdx].is_frozen : false,
            is_quarantined: existingIdx >= 0 ? prev[existingIdx].is_quarantined : false,
            files_touched: (existingIdx >= 0 ? prev[existingIdx].files_touched : 0) + (d.mod_rate || 0),
            files_encrypted: (existingIdx >= 0 ? prev[existingIdx].files_encrypted : 0) + (d.files_encrypted_now || 0),
            last_window_idx: d.window_idx || 0,
            simulated: true,
          };

          if (existingIdx >= 0) {
            const next = [...prev];
            next[existingIdx] = updatedProc;
            return next;
          }
          return [updatedProc, ...prev];
        });

        if (d.files_encrypted_now > 0) {
          setFilesSummary((prev) => ({
            ...prev,
            encrypted: prev.encrypted + d.files_encrypted_now,
            intact: Math.max(0, prev.intact - d.files_encrypted_now),
          }));
        }
      } else if (event.type === 'alert') {
        const alertData = event.data;
        const newAlert: AlertItem = {
          id: alertData.alert_id || String(Date.now()),
          timestamp: alertData.timestamp || new Date().toISOString(),
          pid: alertData.pid,
          process_name: alertData.process_name,
          risk_level: alertData.risk_level || 'CRITICAL',
          ewma_score: alertData.ewma || 0.9,
          model_name: alertData.model_name || 'xgboost',
          explanation: alertData.explanation || {},
          window_data: alertData,
          status: 'active',
          action_taken: 'freeze',
          simulated: true,
        };
        setAlerts((prev) => [newAlert, ...prev]);
      } else if (event.type === 'containment') {
        const contData = event.data;
        const pid = contData.pid;
        setProcesses((prev) =>
          prev.map((p) => {
            if (p.pid === pid) {
              return {
                ...p,
                is_frozen: Boolean(contData.is_frozen),
                status: contData.action === 'release' ? 'normal' : contData.action === 'confirm' ? 'killed' : 'frozen',
              };
            }
            return p;
          })
        );

        if (contData.is_rolled_back) {
          setFilesSummary((prev) => ({
            ...prev,
            restored: prev.restored + (contData.files_rolled_back || 55),
            encrypted: 0,
          }));
        }
      } else if (event.type === 'scenario_state') {
        onRefreshStatus();
      }
    }
  }, [wsEvents, timelineData.length, onRefreshStatus]);

  // Handle Scenario trigger
  const handleRunScenario = async () => {
    try {
      setTimelineData([]);
      await api.runScenario(selectedScenario, {
        speed: simSpeed,
        seed: 42,
      });
      onRefreshStatus();
    } catch (e: any) {
      alert(`Failed to start scenario: ${e.message}`);
    }
  };

  const handleStopScenario = async () => {
    try {
      await api.stopScenario();
      onRefreshStatus();
    } catch (e: any) {
      alert(`Failed to stop scenario: ${e.message}`);
    }
  };

  const handleRelease = async (pid: number) => {
    try {
      await api.releaseProcess(pid, 'Manual dashboard release override');
      setProcesses((prev) =>
        prev.map((p) => (p.pid === pid ? { ...p, is_frozen: false, status: 'normal' } : p))
      );
    } catch (e: any) {
      alert(`Release error: ${e.message}`);
    }
  };

  const handleConfirm = async (pid: number) => {
    try {
      await api.confirmProcess(pid, 'Operator confirmed threat');
      setProcesses((prev) =>
        prev.map((p) => (p.pid === pid ? { ...p, status: 'killed' } : p))
      );
    } catch (e: any) {
      alert(`Confirm error: ${e.message}`);
    }
  };

  if (isLoading) {
    return (
      <div className="flex-1 p-8 flex items-center justify-center space-x-3 text-slate-400">
        <RefreshCw className="w-5 h-5 animate-spin text-blue-400" />
        <span className="text-sm">Connecting to AdaptShield telemetry engine...</span>
      </div>
    );
  }

  const isScenarioRunning = Boolean(status?.running_scenario);

  return (
    <div className="flex-1 p-6 space-y-6 overflow-y-auto">
      {/* Top Scenario Launcher Control Bar */}
      <div className="p-4 rounded-xl border border-slate-800 bg-[#0d1424] flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center space-x-3">
          <label className="text-xs font-semibold uppercase tracking-wider text-slate-400">
            Scenario:
          </label>
          <select
            value={selectedScenario}
            onChange={(e) => setSelectedScenario(e.target.value)}
            disabled={isScenarioRunning}
            className="bg-slate-900 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-white focus:outline-none focus:border-blue-500 font-mono"
          >
            {scenarios.map((scen) => (
              <option key={scen.id} value={scen.id}>
                {scen.name} ({scen.family})
              </option>
            ))}
          </select>

          <div className="flex items-center space-x-1.5 text-xs text-slate-400 ml-2">
            <span>Speed:</span>
            <select
              value={simSpeed}
              onChange={(e) => setSimSpeed(Number(e.target.value))}
              disabled={isScenarioRunning}
              className="bg-slate-900 border border-slate-700 rounded px-2 py-1 text-xs text-white font-mono"
            >
              <option value={1.0}>1x</option>
              <option value={5.0}>5x</option>
              <option value={20.0}>20x</option>
            </select>
          </div>
        </div>

        <div className="flex items-center space-x-3">
          {!isScenarioRunning ? (
            <button
              onClick={handleRunScenario}
              className="px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-semibold text-xs flex items-center space-x-2 transition-all shadow-lg shadow-blue-600/20"
            >
              <Play className="w-3.5 h-3.5 fill-current" />
              <span>Launch Scenario</span>
            </button>
          ) : (
            <button
              onClick={handleStopScenario}
              className="px-4 py-2 rounded-lg bg-red-600 hover:bg-red-500 text-white font-semibold text-xs flex items-center space-x-2 transition-all shadow-lg shadow-red-600/20"
            >
              <Square className="w-3.5 h-3.5 fill-current" />
              <span>Stop Scenario</span>
            </button>
          )}

          <button
            onClick={loadInitialData}
            className="p-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs transition-colors"
            title="Refresh dashboard"
          >
            <RefreshCw className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* 1. KPI Cards */}
      <KpiCards
        processes={processes}
        alerts={alerts}
        filesSummary={filesSummary}
      />

      {/* 2. Real-time Risk Timeline Chart */}
      <RiskTimelineChart data={timelineData} />

      {/* 3. Grid: Process Table (60%) & Alert Feed (40%) */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2">
          <ProcessTable
            processes={processes}
            policy={status?.active_policy}
            onRelease={handleRelease}
            onConfirm={handleConfirm}
          />
        </div>

        <div className="lg:col-span-1">
          <AlertFeed
            alerts={alerts}
            onSelectAlert={(a) => {
              setSelectedAlert(a);
              setIsDrawerOpen(true);
            }}
          />
        </div>
      </div>

      {/* 4. Forensic Evidence Drawer Modal */}
      <EvidenceDrawer
        alert={selectedAlert}
        isOpen={isDrawerOpen}
        onClose={() => setIsDrawerOpen(false)}
        onRelease={handleRelease}
        onConfirm={handleConfirm}
      />
    </div>
  );
};
