import { Shield, Radio, AlertTriangle, RefreshCw, Sparkles, Menu } from 'lucide-react';
import { SystemStatus } from '../../types/api';

interface NavbarProps {
  status: SystemStatus | null;
  wsConnected: boolean;
  isSidebarOpen?: boolean;
  onToggleSidebar?: () => void;
  onPolicyChange?: (policy: string) => void;
  onResetStorm?: () => void;
  onOpenGuidedDemo?: () => void;
}

export const Navbar: React.FC<NavbarProps> = ({
  status,
  wsConnected,
  isSidebarOpen = false,
  onToggleSidebar,
  onPolicyChange,
  onResetStorm,
  onOpenGuidedDemo,
}) => {
  return (
    <header className="h-16 border-b border-[#e5dbe8] bg-white/80 backdrop-blur-md px-6 flex items-center justify-between sticky top-0 z-40 text-[#2c2436] shadow-sm">
      {/* Left: Hamburger, Brand, Simulated Badge, & Guided Demo trigger */}
      <div className="flex items-center space-x-3">
        {onToggleSidebar && (
          <button
            onClick={onToggleSidebar}
            className="p-1.5 rounded-lg text-[#6b5f77] hover:text-[#2c2436] hover:bg-[#f2e9f4] transition-colors mr-1"
            title={isSidebarOpen ? 'Hide Navigation' : 'Open Navigation'}
            aria-label="Toggle navigation menu"
          >
            <Menu className="w-5 h-5" />
          </button>
        )}

        <div className="flex items-center space-x-2 text-[#b56576] font-bold text-lg tracking-wider">
          <Shield className="w-6 h-6 text-[#b56576]" />
          <span>ADAPTSHIELD</span>
        </div>

        {/* Persistent Simulated Demo Data Badge */}
        <div
          data-testid="simulated-badge"
          className="flex items-center space-x-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-[#fef5e8] text-[#9b5825] border border-[#fcdcb8]"
          title="All ransomware behavior is simulated with synthetic telemetry and throwaway virtual files."
        >
          <AlertTriangle className="w-3.5 h-3.5" />
          <span>SIMULATED DEMO DATA</span>
        </div>

        {/* Guided Demo Button */}
        {onOpenGuidedDemo && (
          <button
            onClick={onOpenGuidedDemo}
            className="flex items-center space-x-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-[#eddde5] text-[#6b3a53] border border-[#ddc2d2] hover:bg-[#e4d1dc] transition-colors shadow-sm"
          >
            <Sparkles className="w-3.5 h-3.5 text-[#8a4e6c] animate-spin" />
            <span>Guided Demo (3 Min)</span>
          </button>
        )}
      </div>

      {/* Right: Runtime State, Engine, Policy & Stream Status */}
      <div className="flex items-center space-x-4">
        {/* Active Scenario Indicator */}
        {status?.running_scenario && (
          <div className="flex items-center space-x-1.5 px-2.5 py-1 rounded-md text-xs font-mono bg-[#edf2f9] text-[#3d5c85] border border-[#d2def0] animate-pulse">
            <Radio className="w-3.5 h-3.5 text-[#3d5c85]" />
            <span>RUNNING: {status.running_scenario.scenario_name}</span>
          </div>
        )}

        {/* Panic Switch Warning */}
        {status?.storm_panic && (
          <div className="flex items-center space-x-2 px-2.5 py-1 rounded-md text-xs font-bold bg-[#fdecee] text-[#9e3146] border border-[#f8c4cd]">
            <span>STORM PANIC TRIPPED (MONITOR MODE)</span>
            <button
              onClick={onResetStorm}
              className="px-2 py-0.5 rounded bg-[#b54a5f] hover:bg-[#a13e51] text-white font-medium flex items-center space-x-1"
            >
              <RefreshCw className="w-3 h-3" />
              <span>Reset</span>
            </button>
          </div>
        )}

        {/* Response Policy Selector */}
        <div className="flex items-center space-x-1 text-xs text-[#6b5f77] bg-white border border-[#e2d5e5] rounded-md px-2 py-1 shadow-sm">
          <span className="text-[#6b5f77]">Policy:</span>
          <select
            value={status?.active_policy || 'immediate'}
            onChange={(e) => onPolicyChange?.(e.target.value)}
            className="bg-transparent text-[#2c2436] font-semibold focus:outline-none cursor-pointer"
          >
            <option value="immediate" className="bg-white text-[#2c2436]">Immediate</option>
            <option value="manual" className="bg-white text-[#2c2436]">Manual (Review)</option>
            <option value="none" className="bg-white text-[#2c2436]">None (Audit)</option>
          </select>
        </div>

        {/* Detection Engine Status */}
        <div className="flex items-center space-x-1.5 text-xs bg-white border border-[#e2d5e5] rounded-md px-2.5 py-1 shadow-sm">
          <span className="text-[#6b5f77]">Detection Engine:</span>
          <span className="font-semibold text-[#286b40]">
            Behavioral Core
          </span>
          <span className="text-[10px] text-[#8c7f99] font-mono">
            (<span>{status?.active_detector || 'xgboost'}</span>)
          </span>
        </div>

        {/* WebSocket Live Stream Connection Pill */}
        <div
          className={`flex items-center space-x-1.5 px-2.5 py-1 rounded-full text-xs font-medium border shadow-sm ${
            wsConnected
              ? 'bg-[#e5f5ec] text-[#246e40] border-[#c0e6cf]'
              : 'bg-[#fdecee] text-[#9e3146] border-[#f8c4cd]'
          }`}
        >
          <span className={`w-2 h-2 rounded-full ${wsConnected ? 'bg-[#246e40] animate-ping' : 'bg-[#9e3146]'}`} />
          <span>{wsConnected ? 'Live Stream' : 'Disconnected'}</span>
        </div>
      </div>
    </header>
  );
};
