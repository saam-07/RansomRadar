import { Shield, Radio, AlertTriangle, RefreshCw } from 'lucide-react';
import { SystemStatus } from '../../types/api';

interface NavbarProps {
  status: SystemStatus | null;
  wsConnected: boolean;
  onPolicyChange?: (policy: string) => void;
  onResetStorm?: () => void;
}

export const Navbar: React.FC<NavbarProps> = ({
  status,
  wsConnected,
  onPolicyChange,
  onResetStorm,
}) => {
  return (
    <header className="h-16 border-b border-slate-800 bg-[#0d1527]/90 backdrop-blur-md px-6 flex items-center justify-between sticky top-0 z-40">
      {/* Left: Brand & Simulated Badge */}
      <div className="flex items-center space-x-4">
        <div className="flex items-center space-x-2 text-blue-500 font-bold text-lg tracking-wider">
          <Shield className="w-6 h-6 text-blue-400" />
          <span>ADAPTSHIELD</span>
        </div>

        {/* Persistent Simulated Demo Data Badge */}
        <div
          data-testid="simulated-badge"
          className="flex items-center space-x-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-amber-500/10 text-amber-400 border border-amber-500/30"
          title="All ransomware behavior is simulated with synthetic telemetry and throwaway virtual files."
        >
          <AlertTriangle className="w-3.5 h-3.5" />
          <span>SIMULATED DEMO DATA</span>
        </div>
      </div>

      {/* Right: Runtime State, Model, Policy & Stream Status */}
      <div className="flex items-center space-x-4">
        {/* Active Scenario Indicator */}
        {status?.running_scenario && (
          <div className="flex items-center space-x-1.5 px-2.5 py-1 rounded-md text-xs font-mono bg-blue-500/10 text-blue-400 border border-blue-500/30 animate-pulse">
            <Radio className="w-3.5 h-3.5 text-blue-400" />
            <span>RUNNING: {status.running_scenario.scenario_name}</span>
          </div>
        )}

        {/* Panic Switch Warning */}
        {status?.storm_panic && (
          <div className="flex items-center space-x-2 px-2.5 py-1 rounded-md text-xs font-bold bg-red-500/20 text-red-400 border border-red-500/40">
            <span>STORM PANIC TRIPPED (MONITOR MODE)</span>
            <button
              onClick={onResetStorm}
              className="px-2 py-0.5 rounded bg-red-600 hover:bg-red-500 text-white font-medium flex items-center space-x-1"
            >
              <RefreshCw className="w-3 h-3" />
              <span>Reset</span>
            </button>
          </div>
        )}

        {/* Response Policy Selector */}
        <div className="flex items-center space-x-1 text-xs text-slate-400 bg-slate-900 border border-slate-800 rounded-md px-2 py-1">
          <span className="text-slate-400">Policy:</span>
          <select
            value={status?.active_policy || 'immediate'}
            onChange={(e) => onPolicyChange?.(e.target.value)}
            className="bg-transparent text-slate-200 font-semibold focus:outline-none cursor-pointer"
          >
            <option value="immediate" className="bg-slate-900 text-slate-200">Immediate</option>
            <option value="manual" className="bg-slate-900 text-slate-200">Manual (Review)</option>
            <option value="none" className="bg-slate-900 text-slate-200">None (Audit)</option>
          </select>
        </div>

        {/* Active Detector & Data Origin */}
        <div className="flex items-center space-x-1.5 text-xs bg-slate-900 border border-slate-800 rounded-md px-2.5 py-1">
          <span className="text-slate-400">Detector:</span>
          <span className="font-semibold text-emerald-400">
            {status?.active_detector || 'xgboost'}
          </span>
          <span className="text-[10px] uppercase font-mono px-1 rounded bg-slate-800 text-slate-400">
            {status?.data_source || 'synthetic'}
          </span>
        </div>

        {/* WebSocket Live Stream Connection Pill */}
        <div
          className={`flex items-center space-x-1.5 px-2.5 py-1 rounded-full text-xs font-medium border ${
            wsConnected
              ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
              : 'bg-red-500/10 text-red-400 border-red-500/30'
          }`}
        >
          <span className={`w-2 h-2 rounded-full ${wsConnected ? 'bg-emerald-400 animate-ping' : 'bg-red-400'}`} />
          <span>{wsConnected ? 'Live Stream' : 'Disconnected'}</span>
        </div>
      </div>
    </header>
  );
};
