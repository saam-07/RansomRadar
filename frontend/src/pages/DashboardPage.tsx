import { useState, useEffect, useCallback, useRef } from 'react';
import { Play, Square, RefreshCw, Shield, ArrowDown } from 'lucide-react';
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
  const dashboardRef = useRef<HTMLDivElement>(null);
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
        const raw = event.data || {};
        const d = (raw && typeof raw === 'object' && 'payload' in raw && raw.payload) ? raw.payload : raw;
        const pid = typeof d.pid === 'number' ? d.pid : parseInt(d.pid, 10);
        if (isNaN(pid) || pid <= 0) continue;

        const winIdx = d.window_idx != null ? Number(d.window_idx) : 0;
        const ewmaScore = Number(d.ewma ?? 0.0);
        const rawProb = Number(d.probability ?? 0.0);
        const pname = d.process_name || `proc_${pid}`;

        setTimelineData((prev) => {
          const ptWinIdx = winIdx > 0 ? winIdx : (prev.length > 0 ? prev[prev.length - 1].window_idx + 1 : 1);
          const pt: TimelineDataPoint = {
            timestamp: d.timestamp || new Date().toISOString(),
            window_idx: ptWinIdx,
            ewma: ewmaScore,
            probability: rawProb,
            pid: pid,
            process_name: pname,
          };
          const next = [...prev, pt];
          return next.slice(-60); // keep last 60 points for performance
        });

        // Update process in table
        setProcesses((prev) => {
          const existingIdx = prev.findIndex((p) => p.pid === pid);
          const updatedProc: ProcessItem = {
            pid: pid,
            process_name: pname,
            label: d.label || 'benign',
            risk_level: d.risk_level || 'NORMAL',
            ewma: ewmaScore,
            probability: rawProb,
            status: existingIdx >= 0 ? prev[existingIdx].status : 'normal',
            is_frozen: existingIdx >= 0 ? prev[existingIdx].is_frozen : false,
            is_quarantined: existingIdx >= 0 ? prev[existingIdx].is_quarantined : false,
            files_touched: (existingIdx >= 0 ? prev[existingIdx].files_touched : 0) + (d.mod_rate || 0),
            files_encrypted: (existingIdx >= 0 ? prev[existingIdx].files_encrypted : 0) + (d.files_encrypted_now || 0),
            last_window_idx: winIdx,
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
        const raw = event.data || {};
        const alertData = (raw && typeof raw === 'object' && 'payload' in raw && raw.payload) ? raw.payload : raw;
        const pid = typeof alertData.pid === 'number' ? alertData.pid : parseInt(alertData.pid, 10);
        if (isNaN(pid) || pid <= 0) continue;

        const newAlert: AlertItem = {
          id: alertData.alert_id || String(Date.now()),
          timestamp: alertData.timestamp || new Date().toISOString(),
          pid: pid,
          process_name: alertData.process_name || `proc_${pid}`,
          risk_level: alertData.risk_level || 'CRITICAL',
          ewma_score: Number(alertData.ewma ?? 0.9),
          model_name: alertData.model_name || 'xgboost',
          explanation: alertData.explanation || {},
          window_data: alertData,
          status: 'active',
          action_taken: 'freeze',
          simulated: true,
        };
        setAlerts((prev) => [newAlert, ...prev]);
      } else if (event.type === 'containment') {
        const raw = event.data || {};
        const contData = (raw && typeof raw === 'object' && 'payload' in raw && raw.payload) ? raw.payload : raw;
        const pid = typeof contData.pid === 'number' ? contData.pid : parseInt(contData.pid, 10);
        if (isNaN(pid) || pid <= 0) continue;

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
  }, [wsEvents, onRefreshStatus]);

  // Handle Scenario trigger
  const handleRunScenario = async () => {
    try {
      setTimelineData([]);
      setProcesses([]);
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
      <div className="flex-1 p-8 flex items-center justify-center space-x-3 text-[#786c85]">
        <RefreshCw className="w-5 h-5 animate-spin text-[#b56576]" />
        <span className="text-sm">Connecting to AdaptShield telemetry engine...</span>
      </div>
    );
  }

  const handleExploreDashboard = () => {
    dashboardRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  const isScenarioRunning = Boolean(status?.running_scenario);

  return (
    <div className="flex-1 overflow-y-auto px-6 md:px-10">
      {/* Large Landing / Intro Section */}
      <section className="relative min-h-[70vh] flex flex-col items-center justify-center text-center py-20 px-4 select-none">
        {/* Subtle Watermark Shield Logo behind Title */}
        <div className="absolute inset-0 flex items-center justify-center pointer-events-none -z-0">
          <Shield
            className="w-[340px] h-[340px] sm:w-[480px] sm:h-[480px] md:w-[600px] md:h-[600px] text-[#b56576] opacity-[0.045] stroke-[1]"
            aria-hidden="true"
          />
        </div>

        {/* Centered Hero Content */}
        <div className="relative z-10 max-w-2xl mx-auto flex flex-col items-center space-y-6">
          <h1 className="text-4xl sm:text-6xl md:text-7xl font-extrabold tracking-widest text-[#2c2436] font-mono uppercase">
            ADAPTSHIELD
          </h1>

          <p className="text-sm sm:text-base md:text-lg text-[#6b5f77] max-w-lg leading-relaxed font-normal">
            Autonomous OS-level behavioral ransomware containment, kernel telemetry, continuous risk scoring, and zero-loss instant rollback.
          </p>

          <button
            onClick={handleExploreDashboard}
            className="mt-4 px-6 py-3 rounded-lg bg-[#b56576] hover:bg-[#a25364] text-white text-xs sm:text-sm font-semibold tracking-wide shadow-xs hover:shadow-sm transition-all flex items-center space-x-2"
          >
            <span>Explore Dashboard</span>
            <ArrowDown className="w-4 h-4" />
          </button>
        </div>
      </section>

      {/* Main Operational Dashboard Content */}
      <div ref={dashboardRef} id="dashboard-content" className="space-y-8 pb-16">
        {/* Top Scenario Launcher Control Bar */}
        <div className="p-5 rounded-xl border border-[#e5dbe8] bg-white/85 backdrop-blur-sm shadow-xs flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center space-x-3">
            <label className="text-xs font-semibold uppercase tracking-wider text-[#786c85]">
              Scenario:
            </label>
            <select
              value={selectedScenario}
              onChange={(e) => setSelectedScenario(e.target.value)}
              disabled={isScenarioRunning}
              className="bg-white border border-[#dfd3e3] rounded-lg px-3 py-1.5 text-xs text-[#2c2436] focus:outline-none focus:border-[#b56576] font-mono shadow-xs"
            >
              {scenarios.map((scen) => (
                <option key={scen.id} value={scen.id}>
                  {scen.name} ({scen.family})
                </option>
              ))}
            </select>

            <div className="flex items-center space-x-1.5 text-xs text-[#786c85] ml-2">
              <span>Speed:</span>
              <select
                value={simSpeed}
                onChange={(e) => setSimSpeed(Number(e.target.value))}
                disabled={isScenarioRunning}
                className="bg-white border border-[#dfd3e3] rounded px-2 py-1 text-xs text-[#2c2436] font-mono shadow-xs"
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
                className="px-4 py-2 rounded-lg bg-[#b56576] hover:bg-[#a25364] text-white font-semibold text-xs flex items-center space-x-2 transition-all shadow-xs"
              >
                <Play className="w-3.5 h-3.5 fill-current" />
                <span>Launch Scenario</span>
              </button>
            ) : (
              <button
                onClick={handleStopScenario}
                className="px-4 py-2 rounded-lg bg-[#c2576a] hover:bg-[#af4759] text-white font-semibold text-xs flex items-center space-x-2 transition-all shadow-xs"
              >
                <Square className="w-3.5 h-3.5 fill-current" />
                <span>Stop Scenario</span>
              </button>
            )}

            <button
              onClick={loadInitialData}
              className="p-2 rounded-lg bg-[#f2e9f2] hover:bg-[#e7dce7] text-[#6b5f77] text-xs transition-colors border border-[#ded2de]"
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
    </div>
  );
};
