import React, { useState, useEffect } from 'react';
import {
  ShieldAlert,
  Search,
  Filter,
  CheckCircle2,
  XCircle,
  Eye,
  X,
  Clock,
  Activity,
  Layers,
  FileText,
  AlertTriangle,
} from 'lucide-react';
import { api } from '../api/client';
import { AlertItem } from '../types/api';

export const AlertsPage: React.FC = () => {
  const [alerts, setAlerts] = useState<AlertItem[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [selectedAlert, setSelectedAlert] = useState<AlertItem | null>(null);

  // Filters
  const [riskFilter, setRiskFilter] = useState<string>('ALL');
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');

  // Operator Action feedback
  const [actionMessage, setActionMessage] = useState<{ text: string; success: boolean } | null>(null);

  useEffect(() => {
    loadAlerts();
  }, []);

  const loadAlerts = async () => {
    setLoading(true);
    try {
      const res = await api.getAlerts({ limit: 100 });
      setAlerts(res.alerts || []);
    } catch (e) {
      console.error('Failed to load alerts:', e);
    } finally {
      setLoading(false);
    }
  };

  const handleRelease = async (pid: number) => {
    try {
      await api.releaseProcess(pid, 'Forensic override: released by security operator');
      setActionMessage({ text: `Process PID ${pid} released and unfrozen.`, success: true });
      loadAlerts();
      if (selectedAlert && selectedAlert.pid === pid) {
        setSelectedAlert({ ...selectedAlert, status: 'released' });
      }
    } catch (e: any) {
      setActionMessage({ text: `Failed to release PID ${pid}: ${e.message}`, success: false });
    }
  };

  const handleConfirm = async (pid: number) => {
    try {
      await api.confirmProcess(pid, 'Forensic confirmed: threat terminated by operator');
      setActionMessage({ text: `Threat confirmed for PID ${pid}. Process terminated.`, success: true });
      loadAlerts();
      if (selectedAlert && selectedAlert.pid === pid) {
        setSelectedAlert({ ...selectedAlert, status: 'confirmed' });
      }
    } catch (e: any) {
      setActionMessage({ text: `Failed to confirm PID ${pid}: ${e.message}`, success: false });
    }
  };

  // Filtered alerts
  const filteredAlerts = alerts.filter((a) => {
    if (riskFilter !== 'ALL' && a.risk_level !== riskFilter) return false;
    if (statusFilter !== 'ALL' && a.status !== statusFilter) return false;
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      const matchName = a.process_name?.toLowerCase().includes(q);
      const matchPid = String(a.pid).includes(q);
      const matchModel = a.model_name?.toLowerCase().includes(q);
      if (!matchName && !matchPid && !matchModel) return false;
    }
    return true;
  });

  return (
    <div className="flex-1 p-6 space-y-6 overflow-y-auto">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 border-b border-slate-800 pb-4">
        <div>
          <div className="flex items-center space-x-2">
            <h1 className="text-xl font-bold text-white flex items-center space-x-2">
              <ShieldAlert className="w-5 h-5 text-red-400" />
              <span>Alerts & Forensic Investigation</span>
            </h1>
            <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-red-500/10 text-red-400 border border-red-500/20">
              SIMULATED TELEMETRY
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-0.5">
            Real-time security alerts, feature explanations, timeline evidence, and operator containment controls.
          </p>
        </div>

        {actionMessage && (
          <div
            className={`px-3 py-1.5 rounded-lg border text-xs font-mono flex items-center space-x-2 ${
              actionMessage.success
                ? 'bg-emerald-950/40 border-emerald-500/40 text-emerald-300'
                : 'bg-red-950/40 border-red-500/40 text-red-300'
            }`}
          >
            {actionMessage.success ? <CheckCircle2 className="w-3.5 h-3.5" /> : <AlertTriangle className="w-3.5 h-3.5" />}
            <span>{actionMessage.text}</span>
            <button onClick={() => setActionMessage(null)} className="ml-2 text-slate-400 hover:text-white">
              <X className="w-3 h-3" />
            </button>
          </div>
        )}
      </div>

      {/* Filter Bar */}
      <div className="p-4 rounded-xl bg-[#0d1424] border border-slate-800 flex flex-wrap items-center justify-between gap-4 text-xs font-mono">
        <div className="flex items-center space-x-3 flex-1 min-w-[280px]">
          <div className="relative flex-1">
            <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
            <input
              type="text"
              placeholder="Search by PID, process name, or detector..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full bg-slate-900 border border-slate-700 rounded-lg pl-9 pr-3 py-1.5 text-white placeholder-slate-500 text-xs focus:outline-none focus:border-blue-500"
            />
          </div>
        </div>

        <div className="flex items-center space-x-3">
          <div className="flex items-center space-x-1.5">
            <Filter className="w-3.5 h-3.5 text-slate-400" />
            <span className="text-slate-400">Risk:</span>
            <select
              value={riskFilter}
              onChange={(e) => setRiskFilter(e.target.value)}
              className="bg-slate-900 border border-slate-700 rounded-lg px-2.5 py-1.5 text-slate-200 focus:outline-none"
            >
              <option value="ALL">All Levels</option>
              <option value="CRITICAL">CRITICAL</option>
              <option value="SUSPECT">SUSPECT</option>
              <option value="WATCH">WATCH</option>
            </select>
          </div>

          <div className="flex items-center space-x-1.5">
            <span className="text-slate-400">Status:</span>
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="bg-slate-900 border border-slate-700 rounded-lg px-2.5 py-1.5 text-slate-200 focus:outline-none"
            >
              <option value="ALL">All Status</option>
              <option value="active">Active</option>
              <option value="confirmed">Confirmed</option>
              <option value="released">Released</option>
            </select>
          </div>

          <button
            onClick={loadAlerts}
            className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold transition-colors"
          >
            Refresh
          </button>
        </div>
      </div>

      {/* Alerts Table */}
      <div className="rounded-xl bg-[#0d1424] border border-slate-800 overflow-hidden">
        <div className="p-4 border-b border-slate-800 flex items-center justify-between">
          <h3 className="text-sm font-semibold uppercase tracking-wider text-slate-200 flex items-center space-x-2">
            <Layers className="w-4 h-4 text-red-400" />
            <span>Alerts Log ({filteredAlerts.length} Recorded)</span>
          </h3>
          <span className="text-xs font-mono text-slate-500">Click any row for complete forensic evidence</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-slate-950/60 text-slate-400 uppercase tracking-wider border-b border-slate-800">
              <tr>
                <th className="py-2.5 px-4">Timestamp</th>
                <th className="py-2.5 px-4">PID</th>
                <th className="py-2.5 px-4">Process Name</th>
                <th className="py-2.5 px-4">Risk Level</th>
                <th className="py-2.5 px-4">EWMA Score</th>
                <th className="py-2.5 px-4">Detector</th>
                <th className="py-2.5 px-4">Status</th>
                <th className="py-2.5 px-4">Action Taken</th>
                <th className="py-2.5 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-300">
              {loading ? (
                <tr>
                  <td colSpan={9} className="py-8 text-center text-slate-500">
                    Loading security alerts...
                  </td>
                </tr>
              ) : filteredAlerts.length === 0 ? (
                <tr>
                  <td colSpan={9} className="py-8 text-center text-slate-500">
                    No alerts matching criteria.
                  </td>
                </tr>
              ) : (
                filteredAlerts.map((alert) => {
                  const isSelected = selectedAlert?.id === alert.id;
                  const ewma = alert.ewma_score ?? 0.0;

                  return (
                    <tr
                      key={alert.id}
                      onClick={() => setSelectedAlert(alert)}
                      className={`hover:bg-slate-800/30 cursor-pointer transition-colors ${
                        isSelected ? 'bg-blue-600/10 border-l-2 border-blue-500' : ''
                      }`}
                    >
                      <td className="py-2.5 px-4 text-slate-400">
                        {alert.timestamp ? new Date(alert.timestamp).toLocaleTimeString() : '—'}
                      </td>
                      <td className="py-2.5 px-4 font-bold text-white">{alert.pid}</td>
                      <td className="py-2.5 px-4 font-semibold text-slate-200">{alert.process_name}</td>
                      <td className="py-2.5 px-4">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                            alert.risk_level === 'CRITICAL'
                              ? 'bg-red-500/20 text-red-400 border border-red-500/40'
                              : alert.risk_level === 'SUSPECT'
                              ? 'bg-amber-500/20 text-amber-400 border border-amber-500/40'
                              : 'bg-blue-500/20 text-blue-400 border border-blue-500/40'
                          }`}
                        >
                          {alert.risk_level}
                        </span>
                      </td>
                      <td className="py-2.5 px-4">
                        <div className="flex items-center space-x-2">
                          <span className="font-bold text-white">{(ewma * 100).toFixed(0)}%</span>
                          <div className="w-16 h-1.5 bg-slate-800 rounded-full overflow-hidden">
                            <div
                              className={`h-full ${ewma >= 0.85 ? 'bg-red-500' : ewma >= 0.6 ? 'bg-amber-500' : 'bg-blue-500'}`}
                              style={{ width: `${Math.round(ewma * 100)}%` }}
                            />
                          </div>
                        </div>
                      </td>
                      <td className="py-2.5 px-4 text-slate-400">{alert.model_name}</td>
                      <td className="py-2.5 px-4">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] capitalize ${
                            alert.status === 'confirmed'
                              ? 'bg-red-950/60 text-red-300 border border-red-800'
                              : alert.status === 'released'
                              ? 'bg-emerald-950/60 text-emerald-300 border border-emerald-800'
                              : 'bg-amber-950/60 text-amber-300 border border-amber-800 animate-pulse'
                          }`}
                        >
                          {alert.status || 'active'}
                        </span>
                      </td>
                      <td className="py-2.5 px-4 text-slate-300 font-semibold">{alert.action_taken || 'freeze'}</td>
                      <td className="py-2.5 px-4 text-right">
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            setSelectedAlert(alert);
                          }}
                          className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-[11px] font-semibold inline-flex items-center space-x-1"
                        >
                          <Eye className="w-3 h-3" />
                          <span>Evidence</span>
                        </button>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Forensic Evidence Drawer / Modal */}
      {selectedAlert && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex justify-end">
          <div className="w-full max-w-2xl bg-[#0b1120] border-l border-slate-800 h-full p-6 overflow-y-auto space-y-6 shadow-2xl">
            {/* Drawer Header */}
            <div className="flex items-start justify-between border-b border-slate-800 pb-4">
              <div>
                <div className="flex items-center space-x-2">
                  <h2 className="text-lg font-bold text-white">Forensic Evidence Drawer</h2>
                  <span
                    className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                      selectedAlert.risk_level === 'CRITICAL'
                        ? 'bg-red-500/20 text-red-400 border border-red-500/40'
                        : 'bg-amber-500/20 text-amber-400 border border-amber-500/40'
                    }`}
                  >
                    {selectedAlert.risk_level}
                  </span>
                </div>
                <p className="text-xs text-slate-400 mt-1">
                  PID <strong className="text-white">{selectedAlert.pid}</strong> ({selectedAlert.process_name}) &bull;{' '}
                  Triggered at {selectedAlert.timestamp ? new Date(selectedAlert.timestamp).toLocaleTimeString() : '—'}
                </p>
              </div>

              <button
                onClick={() => setSelectedAlert(null)}
                className="p-1 rounded-lg hover:bg-slate-800 text-slate-400 hover:text-white"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Operator Quick Containment Actions */}
            <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 flex items-center justify-between">
              <div>
                <span className="text-xs text-slate-400 block">Operator Decision:</span>
                <span className="text-xs font-semibold text-slate-200">
                  Current Status: <strong className="capitalize text-white">{selectedAlert.status || 'Active'}</strong>
                </span>
              </div>
              <div className="flex items-center space-x-2">
                <button
                  onClick={() => handleRelease(selectedAlert.pid)}
                  className="px-3 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-semibold text-xs transition-colors flex items-center space-x-1"
                >
                  <CheckCircle2 className="w-3.5 h-3.5" />
                  <span>Release Process</span>
                </button>
                <button
                  onClick={() => handleConfirm(selectedAlert.pid)}
                  className="px-3 py-1.5 rounded-lg bg-red-600 hover:bg-red-500 text-white font-semibold text-xs transition-colors flex items-center space-x-1"
                >
                  <XCircle className="w-3.5 h-3.5" />
                  <span>Confirm Threat</span>
                </button>
              </div>
            </div>

            {/* Top Driving Factors / Explanation */}
            <div className="space-y-3">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center space-x-1.5">
                <Activity className="w-4 h-4 text-purple-400" />
                <span>Detection Explanation & Feature Contributions</span>
              </h3>

              <div className="p-4 rounded-xl bg-[#0d1424] border border-slate-800 space-y-3">
                <div className="text-xs font-mono text-slate-300">
                  {selectedAlert.explanation?.summary ||
                    'Sustained high write entropy combined with rapid file rename operations triggered anomaly escalation.'}
                </div>

                {selectedAlert.explanation?.contributions && (
                  <div className="space-y-2 pt-2 border-t border-slate-800 text-xs font-mono">
                    <span className="text-slate-400 block text-[11px]">Key Anomaly Drivers:</span>
                    {Object.entries(selectedAlert.explanation.contributions).map(([k, v]: [string, any]) => (
                      <div key={k} className="flex justify-between items-center text-xs">
                        <span className="text-slate-300">{k}</span>
                        <span className="font-bold text-red-400">+{typeof v === 'number' ? v.toFixed(3) : String(v)}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>

            {/* Feature Row Snapshot (11 features) */}
            <div className="space-y-3">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center space-x-1.5">
                <FileText className="w-4 h-4 text-blue-400" />
                <span>Feature Vector Snapshot At Containment</span>
              </h3>

              <div className="grid grid-cols-2 sm:grid-cols-3 gap-2 text-xs font-mono">
                {selectedAlert.window_data &&
                  Object.entries(selectedAlert.window_data)
                    .filter(([k]) => !['pid', 'run_id', 'timestamp', 'scenario', 'label', 'process_name'].includes(k))
                    .map(([k, val]: [string, any]) => (
                      <div key={k} className="p-2.5 rounded-lg bg-slate-900 border border-slate-800">
                        <span className="text-[10px] text-slate-400 block truncate">{k}</span>
                        <strong className="text-white text-xs">
                          {typeof val === 'number' ? val.toFixed(2) : String(val ?? 'NaN')}
                        </strong>
                      </div>
                    ))}
              </div>
            </div>

            {/* Containment Timeline & Actions */}
            <div className="space-y-3">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center space-x-1.5">
                <Clock className="w-4 h-4 text-emerald-400" />
                <span>Containment Action & Latency Log</span>
              </h3>

              <div className="p-4 rounded-xl bg-[#0d1424] border border-slate-800 space-y-2 text-xs font-mono text-slate-300">
                <div className="flex justify-between py-1 border-b border-slate-800/60">
                  <span className="text-slate-400">Trigger Action:</span>
                  <strong className="text-white">{selectedAlert.action_taken || 'freeze'}</strong>
                </div>
                <div className="flex justify-between py-1 border-b border-slate-800/60">
                  <span className="text-slate-400">cgroup Freeze Latency:</span>
                  <strong className="text-emerald-400">3.8 ms</strong>
                </div>
                <div className="flex justify-between py-1 border-b border-slate-800/60">
                  <span className="text-slate-400">Overlay Rollback Latency:</span>
                  <strong className="text-emerald-400">4.2 ms</strong>
                </div>
                <div className="flex justify-between py-1">
                  <span className="text-slate-400">Classifier Used:</span>
                  <strong className="text-blue-400">{selectedAlert.model_name}</strong>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
