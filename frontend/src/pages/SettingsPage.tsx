import React, { useState, useEffect } from 'react';
import {
  Settings,
  Sliders,
  Shield,
  RotateCcw,
  Save,
  CheckCircle2,
  AlertTriangle,
  Plus,
  Trash2,
  Lock,
} from 'lucide-react';
import { api } from '../api/client';

export const SettingsPage: React.FC = () => {
  const [loading, setLoading] = useState<boolean>(true);
  const [saveStatus, setSaveStatus] = useState<{ message: string; success: boolean } | null>(null);

  // Settings State
  const [theta0, setTheta0] = useState<number>(0.5);
  const [windowDuration, setWindowDuration] = useState<number>(2.0);
  const [ewmaAlpha, setEwmaAlpha] = useState<number>(0.4);
  const [watchThreshold, setWatchThreshold] = useState<number>(0.3);
  const [suspectThreshold, setSuspectThreshold] = useState<number>(0.6);
  const [criticalThreshold, setCriticalThreshold] = useState<number>(0.85);
  const [criticalConfirmWindows, setCriticalConfirmWindows] = useState<number>(2);
  const [policy, setPolicy] = useState<string>('immediate');
  const [autoResolveTimeout, setAutoResolveTimeout] = useState<number>(10.0);
  const [panicStormThreshold, setPanicStormThreshold] = useState<number>(5);
  const [allowlist, setAllowlist] = useState<string[]>([
    'rsync',
    'tar',
    'postgres',
    'mysqld',
    'sshd',
    'dockerd',
    'systemd',
  ]);
  const [newAllowlistName, setNewAllowlistName] = useState<string>('');

  useEffect(() => {
    loadSettings();
  }, []);

  const loadSettings = async () => {
    setLoading(true);
    try {
      const res: any = await api.getSettings();
      if (res) {
        setTheta0(res.theta0 ?? 0.5);
        setWindowDuration(res.window ?? 2.0);
        setEwmaAlpha(res.ewma_alpha ?? 0.4);
        setWatchThreshold(res.watch_threshold ?? 0.3);
        setSuspectThreshold(res.suspect_threshold ?? 0.6);
        setCriticalThreshold(res.critical_threshold ?? 0.85);
        setCriticalConfirmWindows(res.critical_confirm_windows ?? 2);
        setPolicy(res.policy || 'immediate');
        setAutoResolveTimeout(res.auto_resolve_timeout ?? 10.0);
        setPanicStormThreshold(res.panic_storm_threshold ?? 5);
        if (res.allowlist) setAllowlist(res.allowlist);
      }
    } catch (e) {
      console.error('Failed to load settings:', e);
    } finally {
      setLoading(false);
    }
  };

  const handleSave = async () => {
    try {
      await api.updateSettings({
        theta0,
        window: windowDuration,
        ewma_alpha: ewmaAlpha,
        watch_threshold: watchThreshold,
        suspect_threshold: suspectThreshold,
        critical_threshold: criticalThreshold,
        critical_confirm_windows: criticalConfirmWindows,
        policy,
        auto_resolve_timeout: autoResolveTimeout,
        panic_storm_threshold: panicStormThreshold,
        allowlist,
      });
      setSaveStatus({ message: 'Settings successfully updated and applied.', success: true });
      setTimeout(() => setSaveStatus(null), 4000);
    } catch (e: any) {
      setSaveStatus({ message: `Failed to save settings: ${e.message}`, success: false });
    }
  };

  const handleResetDemoState = async () => {
    if (!window.confirm('Reset demo state? This clears active scenarios, files, and re-seeds baseline data.')) {
      return;
    }
    try {
      await api.resetDemoState();
      setSaveStatus({ message: 'Demo environment reset to clean initial baseline.', success: true });
      loadSettings();
      setTimeout(() => setSaveStatus(null), 4000);
    } catch (e: any) {
      setSaveStatus({ message: `Failed to reset demo: ${e.message}`, success: false });
    }
  };

  const handleAddAllowlist = (e: React.FormEvent) => {
    e.preventDefault();
    const clean = newAllowlistName.trim().toLowerCase();
    if (!clean) return;
    if (!allowlist.includes(clean)) {
      setAllowlist([...allowlist, clean]);
    }
    setNewAllowlistName('');
  };

  const handleRemoveAllowlist = (name: string) => {
    setAllowlist(allowlist.filter((n) => n !== name));
  };

  return (
    <div className="flex-1 p-6 space-y-6 overflow-y-auto">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 border-b border-[#ebdbe8] pb-4">
        <div>
          <div className="flex items-center space-x-2">
            <h1 className="text-xl font-bold text-[#2c2436] flex items-center space-x-2">
              <Settings className="w-5 h-5 text-[#b56576]" />
              <span>Engine Settings & Containment Safety Rails</span>
            </h1>
            <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-[#eddce5] text-[#9d7394] border border-[#dcbcd1]">
              RUNTIME CONFIG
            </span>
            {loading && <span className="text-[10px] text-[#786c85] font-mono">Loading...</span>}
          </div>
          <p className="text-xs text-[#786c85] mt-0.5">
            Configure risk thresholds, EWMA smoothing, containment semantics, process allowlist, and reset demo state.
          </p>
        </div>

        <div className="flex items-center space-x-3">
          {saveStatus && (
            <div
              className={`px-3 py-1.5 rounded-lg border text-xs font-mono flex items-center space-x-1.5 ${
                saveStatus.success
                  ? 'bg-[#e5f5ec] border-[#c0e6cf] text-[#246e40]'
                  : 'bg-[#fdecee] border-[#f8c4cd] text-[#9e3146]'
              }`}
            >
              {saveStatus.success ? <CheckCircle2 className="w-3.5 h-3.5" /> : <AlertTriangle className="w-3.5 h-3.5" />}
              <span>{saveStatus.message}</span>
            </div>
          )}

          <button
            onClick={handleSave}
            className="px-4 py-2 rounded-lg bg-[#b56576] hover:bg-[#a25364] text-white font-semibold text-xs transition-colors flex items-center space-x-1.5 shadow-sm"
          >
            <Save className="w-4 h-4" />
            <span>Save Settings</span>
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* 1. Risk Scoring & EWMA Tuning */}
        <div className="p-6 rounded-xl bg-white/85 border border-[#e5dbe8] shadow-sm space-y-5">
          <h3 className="text-sm font-semibold uppercase tracking-wider text-[#2c2436] flex items-center space-x-2">
            <Sliders className="w-4 h-4 text-[#9d7394]" />
            <span>Risk Scoring & EWMA Tuning</span>
          </h3>

          <div className="space-y-4 text-xs font-mono">
            <div>
              <div className="flex justify-between text-[#4a3f55] mb-1">
                <span>EWMA Alpha (Smoothing Factor):</span>
                <strong className="text-[#9d7394] font-bold">{ewmaAlpha.toFixed(2)}</strong>
              </div>
              <input
                type="range"
                min="0.05"
                max="0.95"
                step="0.05"
                value={ewmaAlpha}
                onChange={(e) => setEwmaAlpha(parseFloat(e.target.value))}
                className="w-full accent-[#9d7394]"
              />
              <span className="text-[10px] text-[#8c7f99]">Higher alpha responds faster to sudden spikes; lower alpha reduces noise.</span>
            </div>

            <div>
              <div className="flex justify-between text-[#4a3f55] mb-1">
                <span>Window Duration (Seconds):</span>
                <strong className="text-[#9d7394] font-bold">{windowDuration.toFixed(1)}s</strong>
              </div>
              <input
                type="range"
                min="0.5"
                max="10.0"
                step="0.5"
                value={windowDuration}
                onChange={(e) => setWindowDuration(parseFloat(e.target.value))}
                className="w-full accent-[#9d7394]"
              />
            </div>

            <div>
              <div className="flex justify-between text-[#4a3f55] mb-1">
                <span>Classifier Threshold (\theta_0):</span>
                <strong className="text-[#9d7394] font-bold">{theta0.toFixed(2)}</strong>
              </div>
              <input
                type="range"
                min="0.1"
                max="0.9"
                step="0.05"
                value={theta0}
                onChange={(e) => setTheta0(parseFloat(e.target.value))}
                className="w-full accent-[#9d7394]"
              />
            </div>

            <div className="pt-3 border-t border-[#ebdbe8] space-y-3">
              <span className="text-[#786c85] font-semibold block">State Escalation Thresholds:</span>
              <div className="grid grid-cols-3 gap-3">
                <div className="p-3 rounded-lg bg-[#fcfaf8] border border-[#ebdbe8]">
                  <span className="text-[10px] text-[#3d5c85] block font-bold mb-1">WATCH</span>
                  <input
                    type="number"
                    step="0.05"
                    min="0.1"
                    max="0.9"
                    value={watchThreshold}
                    onChange={(e) => setWatchThreshold(parseFloat(e.target.value))}
                    className="w-full bg-white border border-[#d8c8dc] rounded px-2 py-1 text-[#2c2436] text-xs focus:outline-none focus:border-[#b56576]"
                  />
                </div>
                <div className="p-3 rounded-lg bg-[#fcfaf8] border border-[#ebdbe8]">
                  <span className="text-[10px] text-[#9b5825] block font-bold mb-1">SUSPECT</span>
                  <input
                    type="number"
                    step="0.05"
                    min="0.1"
                    max="0.9"
                    value={suspectThreshold}
                    onChange={(e) => setSuspectThreshold(parseFloat(e.target.value))}
                    className="w-full bg-white border border-[#d8c8dc] rounded px-2 py-1 text-[#2c2436] text-xs focus:outline-none focus:border-[#b56576]"
                  />
                </div>
                <div className="p-3 rounded-lg bg-[#fcfaf8] border border-[#ebdbe8]">
                  <span className="text-[10px] text-[#9e3146] block font-bold mb-1">CRITICAL</span>
                  <input
                    type="number"
                    step="0.05"
                    min="0.1"
                    max="0.99"
                    value={criticalThreshold}
                    onChange={(e) => setCriticalThreshold(parseFloat(e.target.value))}
                    className="w-full bg-white border border-[#d8c8dc] rounded px-2 py-1 text-[#2c2436] text-xs focus:outline-none focus:border-[#b56576]"
                  />
                </div>
              </div>

              <div>
                <div className="flex justify-between text-[#4a3f55] mb-1">
                  <span>Critical Confirm Windows:</span>
                  <strong className="text-[#2c2436] font-bold">{criticalConfirmWindows} windows</strong>
                </div>
                <input
                  type="range"
                  min="1"
                  max="5"
                  step="1"
                  value={criticalConfirmWindows}
                  onChange={(e) => setCriticalConfirmWindows(parseInt(e.target.value))}
                  className="w-full accent-[#b56576]"
                />
                <span className="text-[10px] text-[#8c7f99]">Requires N consecutive windows above critical threshold before containment.</span>
              </div>
            </div>
          </div>
        </div>

        {/* 2. Containment Policy & Safety Rails */}
        <div className="p-6 rounded-xl bg-white/85 border border-[#e5dbe8] shadow-sm space-y-5">
          <h3 className="text-sm font-semibold uppercase tracking-wider text-[#2c2436] flex items-center space-x-2">
            <Shield className="w-4 h-4 text-[#246e40]" />
            <span>Containment Policy & Safety Rails</span>
          </h3>

          <div className="space-y-4 text-xs font-mono">
            <div>
              <label className="text-[#786c85] block mb-1">Response Policy Semantics:</label>
              <select
                value={policy}
                onChange={(e) => setPolicy(e.target.value)}
                className="w-full bg-white border border-[#d8c8dc] rounded-lg px-3 py-2 text-[#2c2436] capitalize focus:outline-none focus:border-[#b56576]"
              >
                <option value="immediate">Immediate (Auto freeze & rollback on CRITICAL)</option>
                <option value="manual">Manual (Freeze process, require operator confirm/release)</option>
                <option value="none">None (Monitor only, zero containment actions)</option>
              </select>
            </div>

            <div>
              <div className="flex justify-between text-[#4a3f55] mb-1">
                <span>Manual Auto-Resolve Timeout:</span>
                <strong className="text-[#246e40] font-bold">{autoResolveTimeout.toFixed(0)}s</strong>
              </div>
              <input
                type="range"
                min="5"
                max="60"
                step="5"
                value={autoResolveTimeout}
                onChange={(e) => setAutoResolveTimeout(parseFloat(e.target.value))}
                className="w-full accent-[#5b9e75]"
              />
              <span className="text-[10px] text-[#8c7f99]">Auto-terminates or unfreezes process if operator does not respond.</span>
            </div>

            <div>
              <div className="flex justify-between text-[#4a3f55] mb-1">
                <span>Storm Panic Switch Threshold:</span>
                <strong className="text-[#9b5825] font-bold">{panicStormThreshold} distinct PIDs</strong>
              </div>
              <input
                type="range"
                min="2"
                max="15"
                step="1"
                value={panicStormThreshold}
                onChange={(e) => setPanicStormThreshold(parseInt(e.target.value))}
                className="w-full accent-[#d97736]"
              />
              <span className="text-[10px] text-[#8c7f99]">
                Automatically drops to monitor mode if {panicStormThreshold}+ PIDs trigger critical simultaneously.
              </span>
            </div>

            {/* Allowlist Editor */}
            <div className="pt-3 border-t border-[#ebdbe8] space-y-2">
              <span className="text-[#786c85] font-semibold block flex items-center space-x-1.5">
                <Lock className="w-3.5 h-3.5 text-[#b56576]" />
                <span>Protected Application Allowlist (Never Contained):</span>
              </span>

              <div className="flex flex-wrap gap-1.5 max-h-28 overflow-y-auto p-2 rounded-lg bg-[#fcfaf8] border border-[#ebdbe8]">
                {allowlist.map((name) => (
                  <span
                    key={name}
                    className="inline-flex items-center space-x-1 px-2 py-0.5 rounded bg-[#f2e9f2] text-[#6b5f77] border border-[#e0d3e5] text-[11px]"
                  >
                    <span>{name}</span>
                    <button
                      onClick={() => handleRemoveAllowlist(name)}
                      className="text-[#8c7f99] hover:text-[#9e3146]"
                    >
                      <Trash2 className="w-3 h-3" />
                    </button>
                  </span>
                ))}
              </div>

              <form onSubmit={handleAddAllowlist} className="flex space-x-2 pt-1">
                <input
                  type="text"
                  placeholder="Add process name (e.g. nginx, redis)..."
                  value={newAllowlistName}
                  onChange={(e) => setNewAllowlistName(e.target.value)}
                  className="flex-1 bg-white border border-[#d8c8dc] rounded-lg px-3 py-1.5 text-[#2c2436] text-xs focus:outline-none focus:border-[#b56576]"
                />
                <button
                  type="submit"
                  className="px-3 py-1.5 rounded-lg bg-[#f2e9f2] hover:bg-[#e7dce7] text-[#6b5f77] border border-[#e0d3e5] font-semibold text-xs flex items-center space-x-1"
                >
                  <Plus className="w-3.5 h-3.5" />
                  <span>Add</span>
                </button>
              </form>
            </div>
          </div>
        </div>
      </div>

      {/* 3. Demo Environment Reset Section */}
      <div className="p-6 rounded-xl bg-[#fdecee]/60 border border-[#f8c4cd] space-y-3">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
          <div>
            <h3 className="text-sm font-semibold uppercase tracking-wider text-[#9e3146] flex items-center space-x-2">
              <RotateCcw className="w-4 h-4 text-[#9e3146]" />
              <span>Reset Demo State & Filesystem Baseline</span>
            </h3>
            <p className="text-xs text-[#786c85] mt-1">
              Restores virtual filesystem to 300 intact files, clears active scenarios, resets panic storm switch, and reseeds initial demo run history.
            </p>
          </div>

          <button
            onClick={handleResetDemoState}
            className="px-4 py-2 rounded-lg bg-[#b54a5f] hover:bg-[#9e3146] text-white font-semibold text-xs transition-colors flex items-center space-x-1.5 shadow-sm"
          >
            <RotateCcw className="w-4 h-4" />
            <span>Reset Demo State</span>
          </button>
        </div>
      </div>
    </div>
  );
};
