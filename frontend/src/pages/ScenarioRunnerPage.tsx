import { useState, useEffect, useCallback } from 'react';
import { Play, Pause, Square, RotateCcw, FileText, Cpu } from 'lucide-react';
import { api } from '../api/client';
import { ScenarioDefinition, ScenarioRunDetail, WebSocketEvent } from '../types/api';
import { FilesystemGrid, VirtualFileItem } from '../components/scenarios/FilesystemGrid';
import { ScenarioReportModal } from '../components/scenarios/ScenarioReportModal';

interface ScenarioRunnerPageProps {
  wsEvents: WebSocketEvent[];
  onRefreshStatus?: () => void;
}

export const ScenarioRunnerPage: React.FC<ScenarioRunnerPageProps> = ({
  wsEvents,
  onRefreshStatus,
}) => {
  const [scenarios, setScenarios] = useState<ScenarioDefinition[]>([]);
  const [selectedScenarioId, setSelectedScenarioId] = useState<string>('fast_ransomware');
  const [detector, setDetector] = useState<string>('xgboost');
  const [policy, setPolicy] = useState<string>('immediate');
  const [speed, setSpeed] = useState<number>(5.0);
  const [seed, setSeed] = useState<number>(42);

  const [isRunning, setIsRunning] = useState<boolean>(false);
  const [isPaused, setIsPaused] = useState<boolean>(false);
  const [files, setFiles] = useState<VirtualFileItem[]>([]);
  const [isFrozen, setIsFrozen] = useState<boolean>(false);
  const [currentRunDetail, setCurrentRunDetail] = useState<ScenarioRunDetail | null>(null);
  const [isReportOpen, setIsReportOpen] = useState<boolean>(false);
  const [activePids, setActivePids] = useState<Record<number, { name: string; status: string; is_frozen: boolean }>>({});

  // 1. Initial Load: Scenarios and Virtual Filesystem
  const loadInitialData = useCallback(async () => {
    try {
      const [scenList, fsRes] = await Promise.all([
        api.getScenarios(),
        api.getVirtualFilesystem(),
      ]);
      setScenarios(scenList || []);
      const fileList = fsRes?.summary?.files || [];
      setFiles(fileList);
    } catch (err) {
      console.error('Failed to load scenarios or filesystem:', err);
    }
  }, []);

  useEffect(() => {
    loadInitialData();
  }, [loadInitialData]);

  // 2. React to WebSocket File Damage & Rollback Events
  useEffect(() => {
    if (!wsEvents || wsEvents.length === 0) return;

    for (const evt of wsEvents) {
      if (evt.type === 'file_damage') {
        const raw = evt.data || {};
        const damage = (raw && typeof raw === 'object' && 'payload' in raw && raw.payload) ? raw.payload : raw;
        const affectedIds: string[] = damage.affected_files || [];
        const pid = typeof damage.pid === 'number' ? damage.pid : parseInt(damage.pid, 10);
        if (isNaN(pid) || pid <= 0) continue;

        setFiles((prev) =>
          prev.map((f) => {
            if (f.id && affectedIds.includes(f.id)) {
              return {
                ...f,
                status: 'encrypted',
                encrypted_by_pid: pid,
              };
            }
            return f;
          })
        );

        setActivePids((prev) => ({
          ...prev,
          [pid]: { name: damage.process_name || `PID ${pid}`, status: 'encrypting', is_frozen: false },
        }));
      } else if (evt.type === 'containment') {
        const raw = evt.data || {};
        const cont = (raw && typeof raw === 'object' && 'payload' in raw && raw.payload) ? raw.payload : raw;
        const pid = typeof cont.pid === 'number' ? cont.pid : parseInt(cont.pid, 10);
        if (isNaN(pid) || pid <= 0) continue;

        if (cont.is_frozen) {
          setIsFrozen(true);
        }

        setActivePids((prev) => ({
          ...prev,
          [pid]: {
            name: prev[pid]?.name || `PID ${pid}`,
            status: cont.action === 'release' ? 'normal' : cont.action === 'confirm' ? 'killed' : 'frozen',
            is_frozen: Boolean(cont.is_frozen),
          },
        }));
      } else if (evt.type === 'rollback') {
        // VISIBLE RESTORATION ON ROLLBACK - key demo moment!
        setFiles((prev) =>
          prev.map((f) => {
            if (f.status === 'encrypted' || f.status === 'quarantined') {
              return {
                ...f,
                status: 'restored',
              };
            }
            return f;
          })
        );
      } else if (evt.type === 'scenario_state') {
        const stateData = evt.data;
        if (stateData.state === 'started') {
          setIsRunning(true);
          setIsFrozen(false);
        } else if (stateData.state === 'completed' || stateData.state === 'stopped') {
          setIsRunning(false);
          if (stateData.summary) {
            const sum = stateData.summary;
            const detail: ScenarioRunDetail = {
              id: sum.run_id || 'run-completed',
              scenario_name: sum.scenario,
              detector: sum.detector,
              policy: sum.policy,
              speed: sum.speed,
              seed: sum.seed,
              status: stateData.state,
              started_at: new Date().toISOString(),
              total_windows: sum.total_windows || 0,
              distinct_pids: sum.distinct_pids || 0,
              contained_pids: sum.contained_pids || [],
              time_to_detect_windows: sum.time_to_detect_windows,
              time_to_detect_seconds: sum.time_to_detect_seconds,
              wall_time_seconds: sum.wall_time_seconds,
              files_encrypted: sum.files_encrypted || 0,
              files_restored: sum.files_restored || 0,
              files_intact: sum.files_intact || 0,
              panic_tripped: sum.panic_tripped || false,
              summary: sum,
              simulated: true,
            };
            setCurrentRunDetail(detail);
            setIsReportOpen(true);
          }
          onRefreshStatus?.();
        }
      }
    }
  }, [wsEvents, onRefreshStatus]);

  // 3. Scenario Control Handlers
  const handleRun = async () => {
    try {
      setIsRunning(true);
      setIsFrozen(false);
      setActivePids({});
      await api.runScenario(selectedScenarioId, {
        detector,
        policy,
        speed,
        seed,
      });
      onRefreshStatus?.();
    } catch (e: any) {
      setIsRunning(false);
      alert(`Error starting scenario: ${e.message}`);
    }
  };

  const handleStop = async () => {
    try {
      await api.stopScenario();
      setIsRunning(false);
      onRefreshStatus?.();
    } catch (e: any) {
      alert(`Error stopping scenario: ${e.message}`);
    }
  };

  const handleReset = async () => {
    try {
      setIsRunning(false);
      setIsFrozen(false);
      setActivePids({});
      await api.resetScenarioState();
      await loadInitialData();
      onRefreshStatus?.();
    } catch (e: any) {
      alert(`Error resetting scenario: ${e.message}`);
    }
  };

  const selectedScenObj = scenarios.find((s) => s.id === selectedScenarioId);

  return (
    <div className="flex-1 p-6 space-y-6 overflow-y-auto">
      {/* Page Title & Mission Header */}
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-[#ebdfe9] pb-4">
        <div>
          <h1 className="text-xl font-bold text-[#2c2436] flex items-center space-x-2">
            <span>Automated Scenario Runner & Containment Visualizer</span>
          </h1>
          <p className="text-xs text-[#786c85] mt-0.5">
            Execute realistic threat scenarios, verify reversible overlayfs containment, and inspect independent multi-attacker isolation.
          </p>
        </div>

        {/* Global Controls: Run / Pause / Stop / Reset */}
        <div className="flex items-center space-x-2">
          {!isRunning ? (
            <button
              onClick={handleRun}
              className="px-4 py-2 rounded-xl bg-[#b56576] hover:bg-[#a25364] text-white font-semibold text-xs flex items-center space-x-2 shadow-sm transition-all"
            >
              <Play className="w-3.5 h-3.5 fill-current" />
              <span>Run Scenario</span>
            </button>
          ) : (
            <>
              <button
                onClick={() => setIsPaused(!isPaused)}
                className="px-3.5 py-2 rounded-xl bg-[#d97736] hover:bg-[#c4672b] text-white font-semibold text-xs flex items-center space-x-1.5 transition-colors shadow-xs"
              >
                {isPaused ? <Play className="w-3.5 h-3.5 fill-current" /> : <Pause className="w-3.5 h-3.5 fill-current" />}
                <span>{isPaused ? 'Resume' : 'Pause'}</span>
              </button>
              <button
                onClick={handleStop}
                className="px-3.5 py-2 rounded-xl bg-[#c2576a] hover:bg-[#af4759] text-white font-semibold text-xs flex items-center space-x-1.5 transition-colors shadow-sm"
              >
                <Square className="w-3.5 h-3.5 fill-current" />
                <span>Stop</span>
              </button>
            </>
          )}

          <button
            onClick={handleReset}
            className="px-3.5 py-2 rounded-xl bg-[#f2e9f2] hover:bg-[#e7dce7] text-[#6b5f77] text-xs font-semibold flex items-center space-x-1.5 transition-colors border border-[#ded2de]"
            title="Reset filesystem and detection scorers to baseline"
          >
            <RotateCcw className="w-3.5 h-3.5" />
            <span>Reset</span>
          </button>
        </div>
      </div>

      {/* 8 Scenario Cards Grid */}
      <div>
        <h3 className="text-xs font-semibold uppercase tracking-wider text-[#786c85] mb-3">
          Select Target Scenario (8 Benchmark Scenarios)
        </h3>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
          {scenarios.map((scen) => {
            const isSelected = scen.id === selectedScenarioId;
            const isBenign = scen.family === 'benign';

            return (
              <div
                key={scen.id}
                onClick={() => !isRunning && setSelectedScenarioId(scen.id)}
                className={`p-4 rounded-xl border text-left cursor-pointer transition-all ${
                  isSelected
                    ? 'bg-[#f5eef4] border-[#b56576] shadow-sm'
                    : 'bg-white/85 border-[#e5dbe8] hover:border-[#cfbfd3] shadow-xs'
                } ${isRunning ? 'opacity-60 cursor-not-allowed' : ''}`}
              >
                <div className="flex items-center justify-between mb-2">
                  <span
                    className={`px-2 py-0.5 rounded text-[10px] uppercase font-mono font-bold ${
                      isBenign
                        ? 'bg-[#e5f5ec] text-[#246e40] border border-[#c0e6cf]'
                        : 'bg-[#fdecee] text-[#9e3146] border border-[#f8c4cd]'
                    }`}
                  >
                    {scen.family}
                  </span>
                  <span className="text-[10px] text-[#786c85] font-mono">
                    {scen.duration_windows} windows
                  </span>
                </div>

                <h4 className="text-xs font-bold text-[#2c2436] font-mono leading-tight mb-1">
                  {scen.name}
                </h4>

                <p className="text-[11px] text-[#6e637a] line-clamp-2 leading-relaxed">
                  {scen.description}
                </p>

                <div className="mt-3 pt-2 border-t border-[#ebdfe9] flex items-center justify-between text-[10px] font-mono text-[#786c85]">
                  <span>Expected:</span>
                  <span className="font-semibold text-[#4a4055]">
                    {scen.expected_outcome.replace('_', ' ')}
                  </span>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Execution Controls Toolbar */}
      <div className="p-4 rounded-xl border border-[#e5dbe8] bg-white/85 backdrop-blur-sm shadow-sm flex flex-wrap items-center justify-between gap-4">
        <div className="flex flex-wrap items-center gap-4 text-xs font-mono">
          {/* Active Selection Details */}
          <div>
            <span className="text-[#786c85]">Target:</span>{' '}
            <strong className="text-[#8e455d]">{selectedScenObj?.name || selectedScenarioId}</strong>
          </div>

          {/* Detector */}
          <div className="flex items-center space-x-1.5">
            <span className="text-[#786c85]">Detector:</span>
            <select
              value={detector}
              onChange={(e) => setDetector(e.target.value)}
              disabled={isRunning}
              className="bg-white border border-[#dfd3e3] rounded px-2.5 py-1 text-[#2c2436] focus:outline-none shadow-xs"
            >
              <option value="xgboost">XGBoost (Active)</option>
              <option value="random_forest">Random Forest</option>
              <option value="rule_based">Rule-Based Heuristic</option>
            </select>
          </div>

          {/* Policy */}
          <div className="flex items-center space-x-1.5">
            <span className="text-[#786c85]">Policy:</span>
            <select
              value={policy}
              onChange={(e) => setPolicy(e.target.value)}
              disabled={isRunning}
              className="bg-white border border-[#dfd3e3] rounded px-2.5 py-1 text-[#2c2436] focus:outline-none shadow-xs"
            >
              <option value="immediate">Immediate Containment</option>
              <option value="manual">Manual Operator Review</option>
              <option value="none">Audit Mode (None)</option>
            </select>
          </div>

          {/* Speed */}
          <div className="flex items-center space-x-1.5">
            <span className="text-[#786c85]">Speed:</span>
            <div className="flex items-center space-x-1">
              {[1.0, 5.0, 20.0].map((s) => (
                <button
                  key={s}
                  onClick={() => setSpeed(s)}
                  disabled={isRunning}
                  className={`px-2 py-0.5 rounded border transition-colors ${
                    speed === s
                      ? 'bg-[#b56576] text-white border-[#b56576] font-bold shadow-xs'
                      : 'bg-white text-[#6b5f77] border-[#dfd3e3] hover:text-[#2c2436]'
                  }`}
                >
                  {s}x
                </button>
              ))}
            </div>
          </div>

          {/* Seed */}
          <div className="flex items-center space-x-1.5">
            <span className="text-[#786c85]">Seed:</span>
            <input
              type="number"
              value={seed}
              onChange={(e) => setSeed(Number(e.target.value))}
              disabled={isRunning}
              className="w-16 bg-white border border-[#dfd3e3] rounded px-2 py-0.5 text-[#2c2436] text-center shadow-xs"
            />
          </div>
        </div>

        {/* View Last Report Button */}
        {currentRunDetail && (
          <button
            onClick={() => setIsReportOpen(true)}
            className="px-3 py-1.5 rounded-lg bg-[#f2e9f2] hover:bg-[#e7dce7] text-[#6b5f77] text-xs font-mono flex items-center space-x-1.5 border border-[#ded2de]"
          >
            <FileText className="w-3.5 h-3.5" />
            <span>View Full Report</span>
          </button>
        )}
      </div>

      {/* Multi-Attacker Per-Process Status (Crucial for Mixed Chaos) */}
      {Object.keys(activePids).length > 0 && (
        <div className="p-4 rounded-xl border border-[#e5dbe8] bg-white/85 backdrop-blur-sm shadow-sm">
          <h4 className="text-xs font-semibold uppercase tracking-wider text-[#786c85] mb-2 flex items-center space-x-2">
            <Cpu className="w-4 h-4 text-[#5b82a6]" />
            <span>Independent Process Containment Status</span>
          </h4>
          <div className="flex flex-wrap gap-3">
            {Object.entries(activePids).map(([pid, pinfo]) => (
              <div
                key={pid}
                className={`p-3 rounded-lg border text-xs font-mono flex items-center space-x-3 shadow-xs ${
                  pinfo.is_frozen
                    ? 'bg-[#eef1f8] border-[#d2dbf0] text-[#3d5386]'
                    : 'bg-white border-[#ebdfe9] text-[#4a4055]'
                }`}
              >
                <div>
                  <span className="font-bold text-[#2c2436]">PID {pid}</span> ({pinfo.name})
                </div>
                <span
                  className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                    pinfo.is_frozen
                      ? 'bg-[#eef1f8] text-[#3d5386] border border-[#d2dbf0]'
                      : 'bg-[#f1ebf4] text-[#6b5f77]'
                  }`}
                >
                  {pinfo.status}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* 2. Filesystem Visualization Grid */}
      <FilesystemGrid files={files} isFrozen={isFrozen} />

      {/* 3. Post-run Result Report Modal */}
      <ScenarioReportModal
        run={currentRunDetail}
        isOpen={isReportOpen}
        onClose={() => setIsReportOpen(false)}
      />
    </div>
  );
};
