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
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 border-b border-[#ebdfe9] pb-4">
        <div>
          <div className="flex items-center space-x-2">
            <h1 className="text-xl font-bold text-[#2c2436] flex items-center space-x-2">
              <ShieldAlert className="w-5 h-5 text-[#9e3146]" />
              <span>Alerts & Forensic Investigation</span>
            </h1>
            <span className="text-xs font-mono text-[#9e3146]">
              SIMULATED TELEMETRY
            </span>
          </div>
          <p className="text-xs text-[#786c85] mt-1">
            Real-time security alerts, feature explanations, timeline evidence, and operator containment controls.
          </p>
        </div>

        {actionMessage && (
          <div
            className={`px-3 py-1.5 rounded-lg border text-xs font-mono flex items-center space-x-2 ${
              actionMessage.success
                ? 'bg-[#e5f5ec] border-[#c0e6cf] text-[#246e40]'
                : 'bg-[#fdecee] border-[#f8c4cd] text-[#9e3146]'
            }`}
          >
            {actionMessage.success ? <CheckCircle2 className="w-3.5 h-3.5" /> : <AlertTriangle className="w-3.5 h-3.5" />}
            <span>{actionMessage.text}</span>
            <button onClick={() => setActionMessage(null)} className="ml-2 text-[#786c85] hover:text-[#2c2436]">
              <X className="w-3 h-3" />
            </button>
          </div>
        )}
      </div>

      {/* Filter Bar */}
      <div className="p-4 rounded-xl bg-white/85 border border-[#e5dbe8] shadow-sm flex flex-wrap items-center justify-between gap-4 text-xs font-mono">
        <div className="flex items-center space-x-3 flex-1 min-w-[280px]">
          <div className="relative flex-1">
            <Search className="w-4 h-4 text-[#8c7f99] absolute left-3 top-2.5" />
            <input
              type="text"
              placeholder="Search by PID, process name, or detector..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full bg-white border border-[#dfd3e3] rounded-lg pl-9 pr-3 py-1.5 text-[#2c2436] placeholder-[#8c7f99] text-xs focus:outline-none focus:border-[#b56576] shadow-xs"
            />
          </div>
        </div>

        <div className="flex items-center space-x-3">
          <div className="flex items-center space-x-1.5">
            <Filter className="w-3.5 h-3.5 text-[#786c85]" />
            <span className="text-[#786c85]">Risk:</span>
            <select
              value={riskFilter}
              onChange={(e) => setRiskFilter(e.target.value)}
              className="bg-white border border-[#dfd3e3] rounded-lg px-2.5 py-1.5 text-[#2c2436] focus:outline-none shadow-xs"
            >
              <option value="ALL">All Levels</option>
              <option value="CRITICAL">CRITICAL</option>
              <option value="SUSPECT">SUSPECT</option>
              <option value="WATCH">WATCH</option>
            </select>
          </div>

          <div className="flex items-center space-x-1.5">
            <span className="text-[#786c85]">Status:</span>
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="bg-white border border-[#dfd3e3] rounded-lg px-2.5 py-1.5 text-[#2c2436] focus:outline-none shadow-xs"
            >
              <option value="ALL">All Status</option>
              <option value="active">Active</option>
              <option value="confirmed">Confirmed</option>
              <option value="released">Released</option>
            </select>
          </div>

          <button
            onClick={loadAlerts}
            className="px-3 py-1.5 rounded-lg bg-[#f2e9f2] hover:bg-[#e7dce7] text-[#6b5f77] border border-[#ded2de] text-xs font-semibold transition-colors"
          >
            Refresh
          </button>
        </div>
      </div>

      {/* Alerts Table */}
      <div className="rounded-xl bg-white/85 border border-[#e5dbe8] shadow-sm overflow-hidden">
        <div className="p-4 border-b border-[#ebdfe9] flex items-center justify-between">
          <h3 className="text-sm font-semibold uppercase tracking-wider text-[#2c2436] flex items-center space-x-2">
            <Layers className="w-4 h-4 text-[#9e3146]" />
            <span>Alerts Log ({filteredAlerts.length} Recorded)</span>
          </h3>
          <span className="text-xs font-mono text-[#786c85]">Click any row for complete forensic evidence</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-[#fbf7f9] text-[#71647e] uppercase tracking-wider border-b border-[#ebdfe9]">
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
            <tbody className="divide-y divide-[#ebdfe9] text-[#2c2436]">
              {loading ? (
                <tr>
                  <td colSpan={9} className="py-8 text-center text-[#8c7f99]">
                    Loading security alerts...
                  </td>
                </tr>
              ) : filteredAlerts.length === 0 ? (
                <tr>
                  <td colSpan={9} className="py-8 text-center text-[#8c7f99]">
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
                      className={`hover:bg-[#fbf7f9]/80 cursor-pointer transition-colors ${
                        isSelected ? 'bg-[#f5eef4] border-l-2 border-[#b56576]' : ''
                      }`}
                    >
                      <td className="py-2.5 px-4 text-[#786c85]">
                        {alert.timestamp ? new Date(alert.timestamp).toLocaleTimeString() : '—'}
                      </td>
                      <td className="py-2.5 px-4 font-bold text-[#2c2436]">{alert.pid}</td>
                      <td className="py-2.5 px-4 font-semibold text-[#2c2436]">{alert.process_name}</td>
                      <td className="py-2.5 px-4">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                            alert.risk_level === 'CRITICAL'
                              ? 'bg-[#fdecee] text-[#9e3146] border border-[#f8c4cd]'
                              : alert.risk_level === 'SUSPECT'
                              ? 'bg-[#fef5e8] text-[#9b5825] border border-[#fcdcb8]'
                              : 'bg-[#edf2f9] text-[#3d5c85] border border-[#d2def0]'
                          }`}
                        >
                          {alert.risk_level}
                        </span>
                      </td>
                      <td className="py-2.5 px-4">
                        <div className="flex items-center space-x-2">
                          <span className="font-bold text-[#2c2436]">{(ewma * 100).toFixed(0)}%</span>
                          <div className="w-16 h-1.5 bg-[#ede5ee] rounded-full overflow-hidden">
                            <div
                              className={`h-full ${ewma >= 0.85 ? 'bg-[#b54a5f]' : ewma >= 0.6 ? 'bg-[#d97736]' : 'bg-[#5b82a6]'}`}
                              style={{ width: `${Math.round(ewma * 100)}%` }}
                            />
                          </div>
                        </div>
                      </td>
                      <td className="py-2.5 px-4 text-[#786c85]">{alert.model_name}</td>
                      <td className="py-2.5 px-4">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] capitalize ${
                            alert.status === 'confirmed'
                              ? 'bg-[#fdecee] text-[#9e3146] border border-[#f8c4cd]'
                              : alert.status === 'released'
                              ? 'bg-[#e5f5ec] text-[#246e40] border border-[#c0e6cf]'
                              : 'bg-[#fef5e8] text-[#9b5825] border border-[#fcdcb8] animate-pulse'
                          }`}
                        >
                          {alert.status || 'active'}
                        </span>
                      </td>
                      <td className="py-2.5 px-4 text-[#4a4055] font-semibold">{alert.action_taken || 'freeze'}</td>
                      <td className="py-2.5 px-4 text-right">
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            setSelectedAlert(alert);
                          }}
                          className="px-2 py-1 rounded bg-[#f2e9f2] hover:bg-[#e7dce7] text-[#6b5f77] border border-[#ded2de] text-[11px] font-semibold inline-flex items-center space-x-1 shadow-xs"
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
        <div className="fixed inset-0 z-50 bg-[#2c2436]/40 backdrop-blur-sm flex justify-end">
          <div className="w-full max-w-2xl bg-[#fcfaf8] border-l border-[#e5dbe8] h-full p-6 overflow-y-auto space-y-6 shadow-2xl text-[#2c2436]">
            {/* Drawer Header */}
            <div className="flex items-start justify-between border-b border-[#ebdfe9] pb-4">
              <div>
                <div className="flex items-center space-x-2">
                  <h2 className="text-lg font-bold text-[#2c2436]">Forensic Evidence Drawer</h2>
                  <span
                    className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                      selectedAlert.risk_level === 'CRITICAL'
                        ? 'bg-[#fdecee] text-[#9e3146] border border-[#f8c4cd]'
                        : 'bg-[#fef5e8] text-[#9b5825] border border-[#fcdcb8]'
                    }`}
                  >
                    {selectedAlert.risk_level}
                  </span>
                </div>
                <p className="text-xs text-[#786c85] mt-1">
                  PID <strong className="text-[#2c2436]">{selectedAlert.pid}</strong> ({selectedAlert.process_name}) &bull;{' '}
                  Triggered at {selectedAlert.timestamp ? new Date(selectedAlert.timestamp).toLocaleTimeString() : '—'}
                </p>
              </div>

              <button
                onClick={() => setSelectedAlert(null)}
                className="p-1 rounded-lg hover:bg-[#f3edf6] text-[#786c85] hover:text-[#2c2436]"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Operator Quick Containment Actions */}
            <div className="p-4 rounded-xl bg-white border border-[#e5dbe8] shadow-xs flex items-center justify-between">
              <div>
                <span className="text-xs text-[#786c85] block">Operator Decision:</span>
                <span className="text-xs font-semibold text-[#4a4055]">
                  Current Status: <strong className="capitalize text-[#2c2436]">{selectedAlert.status || 'Active'}</strong>
                </span>
              </div>
              <div className="flex items-center space-x-2">
                <button
                  onClick={() => handleRelease(selectedAlert.pid)}
                  className="px-3 py-1.5 rounded-lg bg-[#e7f4ed] hover:bg-[#d6ede0] text-[#236b3e] border border-[#bfe4cd] font-semibold text-xs transition-colors flex items-center space-x-1 shadow-xs"
                >
                  <CheckCircle2 className="w-3.5 h-3.5" />
                  <span>Release Process</span>
                </button>
                <button
                  onClick={() => handleConfirm(selectedAlert.pid)}
                  className="px-3 py-1.5 rounded-lg bg-[#fdecee] hover:bg-[#fbdde1] text-[#9e3146] border border-[#f7c0ca] font-semibold text-xs transition-colors flex items-center space-x-1 shadow-xs"
                >
                  <XCircle className="w-3.5 h-3.5" />
                  <span>Confirm Threat</span>
                </button>
              </div>
            </div>

            {/* Top Driving Factors / Explanation */}
            <div className="space-y-3">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-[#786c85] flex items-center space-x-1.5">
                <Activity className="w-4 h-4 text-[#8e455d]" />
                <span>Detection Explanation & Feature Contributions</span>
              </h3>

              <div className="p-4 rounded-xl bg-white border border-[#e5dbe8] shadow-xs space-y-3">
                <div className="text-xs font-mono text-[#4a4055]">
                  {selectedAlert.explanation?.summary ||
                    'Sustained high write entropy combined with rapid file rename operations triggered anomaly escalation.'}
                </div>

                {selectedAlert.explanation?.contributions && (
                  <div className="space-y-2 pt-2 border-t border-[#ebdfe9] text-xs font-mono">
                    <span className="text-[#786c85] block text-[11px]">Key Anomaly Drivers:</span>
                    {Object.entries(selectedAlert.explanation.contributions).map(([k, v]: [string, any]) => (
                      <div key={k} className="flex justify-between items-center text-xs">
                        <span className="text-[#4a4055]">{k}</span>
                        <span className="font-bold text-[#9e3146]">+{typeof v === 'number' ? v.toFixed(3) : String(v)}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>

            {/* Feature Row Snapshot (11 features) */}
            <div className="space-y-3">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-[#786c85] flex items-center space-x-1.5">
                <FileText className="w-4 h-4 text-[#5b82a6]" />
                <span>Feature Vector Snapshot At Containment</span>
              </h3>

              <div className="grid grid-cols-2 sm:grid-cols-3 gap-2 text-xs font-mono">
                {selectedAlert.window_data &&
                  Object.entries(selectedAlert.window_data)
                    .filter(([k]) => !['pid', 'run_id', 'timestamp', 'scenario', 'label', 'process_name'].includes(k))
                    .map(([k, val]: [string, any]) => (
                      <div key={k} className="p-2.5 rounded-lg bg-white border border-[#ebdfe9] shadow-xs">
                        <span className="text-[10px] text-[#786c85] block truncate">{k}</span>
                        <strong className="text-[#2c2436] text-xs">
                          {typeof val === 'number' ? val.toFixed(2) : String(val ?? 'NaN')}
                        </strong>
                      </div>
                    ))}
              </div>
            </div>

            {/* Containment Timeline & Actions */}
            <div className="space-y-3">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-[#786c85] flex items-center space-x-1.5">
                <Clock className="w-4 h-4 text-[#246e40]" />
                <span>Containment Action & Latency Log</span>
              </h3>

              <div className="p-4 rounded-xl bg-white border border-[#e5dbe8] shadow-xs space-y-2 text-xs font-mono text-[#4a4055]">
                <div className="flex justify-between py-1 border-b border-[#ebdfe9]">
                  <span className="text-[#786c85]">Trigger Action:</span>
                  <strong className="text-[#2c2436]">{selectedAlert.action_taken || 'freeze'}</strong>
                </div>
                <div className="flex justify-between py-1 border-b border-[#ebdfe9]">
                  <span className="text-[#786c85]">cgroup Freeze Latency:</span>
                  <strong className="text-[#246e40]">3.8 ms</strong>
                </div>
                <div className="flex justify-between py-1 border-b border-[#ebdfe9]">
                  <span className="text-[#786c85]">Overlay Rollback Latency:</span>
                  <strong className="text-[#246e40]">4.2 ms</strong>
                </div>
                <div className="flex justify-between py-1">
                  <span className="text-[#786c85]">Classifier Used:</span>
                  <strong className="text-[#5b82a6]">{selectedAlert.model_name}</strong>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
