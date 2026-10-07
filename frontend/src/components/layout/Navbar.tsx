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
    <header className="h-16 border-b border-[#e5dbe8] bg-white/80 backdrop-blur-md px-6 flex items-center justify-between sticky top-0 z-40 text-[#2c2436] shadow-xs">
      {/* Left: Hamburger, Brand, Simulated Notice, & Guided Demo action */}
      <div className="flex items-center space-x-4">
        {onToggleSidebar && (
          <button
            onClick={onToggleSidebar}
            className="p-1.5 rounded-lg text-[#6b5f77] hover:text-[#2c2436] hover:bg-[#f2e9f4] transition-colors"
            title={isSidebarOpen ? 'Hide Navigation' : 'Open Navigation'}
            aria-label="Toggle navigation menu"
          >
            <Menu className="w-5 h-5" />
          </button>
        )}

        <div className="flex items-center space-x-2 text-[#b56576] font-bold text-lg tracking-wider">
          <Shield className="w-5 h-5 text-[#b56576]" />
          <span>ADAPTSHIELD</span>
        </div>

        {/* Persistent Simulated Demo Data - Clean Simple Text without pill box */}
        <div
          data-testid="simulated-badge"
          className="hidden sm:flex items-center space-x-1 text-xs font-mono text-[#9b5825]"
          title="All ransomware behavior is simulated with synthetic telemetry and throwaway virtual files."
        >
          <AlertTriangle className="w-3.5 h-3.5 opacity-80" />
          <span>SIMULATED DEMO DATA</span>
        </div>

        {/* Guided Demo - Clean Proper Action Button */}
        {onOpenGuidedDemo && (
          <button
            onClick={onOpenGuidedDemo}
            className="flex items-center space-x-1.5 px-3 py-1.5 rounded-md text-xs font-medium bg-[#b56576] hover:bg-[#a25364] text-white transition-colors shadow-xs"
          >
            <Sparkles className="w-3.5 h-3.5" />
            <span>Guided Demo</span>
          </button>
        )}
      </div>

      {/* Right: Runtime State, Engine, Policy & Stream Status */}
      <div className="flex items-center space-x-5">
        {/* Active Scenario Indicator */}
        {status?.running_scenario && (
          <div className="flex items-center space-x-1.5 text-xs font-mono text-[#3d5c85]">
            <Radio className="w-3.5 h-3.5 text-[#3d5c85] animate-pulse" />
            <span>RUNNING: {status.running_scenario.scenario_name}</span>
          </div>
        )}

        {/* Panic Switch Warning */}
        {status?.storm_panic && (
          <div className="flex items-center space-x-2 text-xs font-bold text-[#9e3146]">
            <span>STORM PANIC TRIPPED</span>
            <button
              onClick={onResetStorm}
              className="px-2 py-0.5 rounded bg-[#b54a5f] hover:bg-[#a13e51] text-white font-medium flex items-center space-x-1 shadow-xs"
            >
              <RefreshCw className="w-3 h-3" />
              <span>Reset</span>
            </button>
          </div>
        )}

        {/* Response Policy Selector - Simple Clean Select */}
        <div className="flex items-center space-x-1.5 text-xs text-[#6b5f77]">
          <span>Policy:</span>
          <select
            value={status?.active_policy || 'immediate'}
            onChange={(e) => onPolicyChange?.(e.target.value)}
            className="bg-transparent border-b border-[#cfc0d2] pb-0.5 text-[#2c2436] font-medium focus:outline-none cursor-pointer"
          >
            <option value="immediate" className="bg-white text-[#2c2436]">Immediate</option>
            <option value="manual" className="bg-white text-[#2c2436]">Manual (Review)</option>
            <option value="none" className="bg-white text-[#2c2436]">None (Audit)</option>
          </select>
        </div>

        {/* Detection Engine Status - Clean Text */}
        <div className="hidden md:flex items-center space-x-1.5 text-xs text-[#6b5f77]">
          <span>Engine:</span>
          <span className="font-medium text-[#2c2436]">Behavioral Core</span>
          <span className="text-[11px] text-[#8c7f99] font-mono">
            (<span>{status?.active_detector || 'xgboost'}</span>)
          </span>
        </div>

        {/* Live Stream Connection Status - Clean Simple Text without box */}
        <div className="flex items-center space-x-1.5 text-xs font-medium text-[#246e40]">
          <span className={`w-2 h-2 rounded-full ${wsConnected ? 'bg-[#246e40]' : 'bg-[#9e3146]'}`} />
          <span>{wsConnected ? 'Live Stream' : 'Disconnected'}</span>
        </div>
      </div>
    </header>
  );
};
