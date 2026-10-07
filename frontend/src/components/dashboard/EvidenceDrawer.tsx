import { X, ShieldAlert, Check, AlertOctagon, Terminal } from 'lucide-react';
import { AlertItem } from '../../types/api';

interface EvidenceDrawerProps {
  alert: AlertItem | null;
  isOpen: boolean;
  onClose: () => void;
  onRelease?: (pid: number) => void;
  onConfirm?: (pid: number) => void;
}

export const EvidenceDrawer: React.FC<EvidenceDrawerProps> = ({
  alert,
  isOpen,
  onClose,
  onRelease,
  onConfirm,
}) => {
  if (!isOpen || !alert) return null;

  const expl = alert.explanation || {};
  const contributions = expl.contributions || [];

  return (
    <div className="fixed inset-0 z-50 flex justify-end bg-black/60 backdrop-blur-sm animate-fadeIn">
      <div className="w-full max-w-xl bg-[#0c1222] border-l border-slate-800 h-full overflow-y-auto flex flex-col justify-between shadow-2xl p-6">
        {/* Header */}
        <div>
          <div className="flex items-center justify-between border-b border-slate-800 pb-4">
            <div className="flex items-center space-x-3">
              <div className="p-2 rounded-lg bg-red-500/10 text-red-400 border border-red-500/30">
                <ShieldAlert className="w-5 h-5" />
              </div>
              <div>
                <h2 className="text-base font-bold text-white flex items-center space-x-2">
                  <span>Forensic Alert Evidence</span>
                  <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-red-500/20 text-red-400 border border-red-500/40">
                    CRITICAL
                  </span>
                </h2>
                <p className="text-xs text-slate-400 font-mono mt-0.5">
                  ID: {alert.id.slice(0, 8)}... | PID {alert.pid} ({alert.process_name})
                </p>
              </div>
            </div>

            <button
              onClick={onClose}
              className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
            >
              <X className="w-5 h-5" />
            </button>
          </div>

          {/* Forensic Narrative */}
          <div className="my-5 p-4 rounded-lg bg-red-500/5 border border-red-500/20">
            <div className="flex items-center space-x-2 text-xs font-semibold text-red-400 uppercase tracking-wider mb-1.5">
              <AlertOctagon className="w-4 h-4" />
              <span>Attribution Summary</span>
            </div>
            <p className="text-xs text-slate-300 leading-relaxed font-sans">
              {expl.summary || 'Anomalous behavioral rates and byte entropy triggered critical containment.'}
            </p>
            <div className="flex items-center space-x-4 mt-3 text-[11px] font-mono text-slate-400">
              <div>Detector: <span className="text-emerald-400 font-bold">{alert.model_name}</span></div>
              <div>EWMA Risk: <span className="text-red-400 font-bold">{alert.ewma_score.toFixed(4)}</span></div>
              <div>Action: <span className="text-amber-400 font-bold">{alert.action_taken}</span></div>
            </div>
          </div>

          {/* Feature Contributions Breakdown */}
          <div className="space-y-3 mb-6">
            <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center justify-between">
              <span>Behavioral Feature Attribution</span>
              <span className="text-[11px] font-normal text-slate-400">Tree Contributions / Rules</span>
            </h4>

            {contributions.length === 0 ? (
              <p className="text-xs text-slate-400 italic">No detailed breakdown available for this alert.</p>
            ) : (
              <div className="space-y-2">
                {contributions.map((c, idx) => (
                  <div
                    key={idx}
                    className="p-3 rounded-lg bg-[#090f1d] border border-slate-800/80 space-y-1.5"
                  >
                    <div className="flex items-center justify-between text-xs">
                      <span className="font-mono font-semibold text-blue-400">{c.feature}</span>
                      <span className="font-mono text-slate-200">
                        Value: {typeof c.value === 'number' ? c.value.toFixed(2) : c.value}
                      </span>
                    </div>
                    {c.narrative && (
                      <p className="text-[11px] text-slate-400 font-sans">{c.narrative}</p>
                    )}
                    {c.contribution_score !== undefined && (
                      <div className="flex items-center space-x-2 pt-1">
                        <span className="text-[10px] text-slate-400 font-mono">Impact Score:</span>
                        <div className="h-1.5 flex-1 bg-slate-800 rounded-full overflow-hidden">
                          <div
                            className="h-full bg-red-500 rounded-full"
                            style={{ width: `${Math.min(100, Math.round(c.contribution_score * 100))}%` }}
                          />
                        </div>
                        <span className="text-[10px] font-mono text-red-400">
                          {c.contribution_score.toFixed(3)}
                        </span>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Raw Feature Vector Dump */}
          <div className="space-y-2">
            <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center space-x-2">
              <Terminal className="w-3.5 h-3.5" />
              <span>Observed Window Feature Vector</span>
            </h4>
            <div className="p-3 rounded-lg bg-black/50 border border-slate-800 font-mono text-[11px] text-slate-400 max-h-48 overflow-y-auto">
              <pre>{JSON.stringify(alert.window_data, null, 2)}</pre>
            </div>
          </div>
        </div>

        {/* Footer Actions */}
        <div className="border-t border-slate-800 pt-4 flex items-center justify-between mt-6">
          <div className="text-xs text-slate-400">
            Status: <span className="uppercase font-mono text-white">{alert.status}</span>
          </div>

          <div className="flex items-center space-x-2">
            <button
              disabled={!alert.pid || alert.pid <= 0}
              onClick={() => {
                if (alert.pid && alert.pid > 0) {
                  onRelease?.(alert.pid);
                  onClose();
                }
              }}
              className="px-3 py-1.5 rounded-lg bg-emerald-600/20 hover:bg-emerald-600/30 text-emerald-300 border border-emerald-500/30 text-xs font-semibold flex items-center space-x-1.5 transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
            >
              <Check className="w-3.5 h-3.5" />
              <span>Release Process</span>
            </button>
            <button
              disabled={!alert.pid || alert.pid <= 0}
              onClick={() => {
                if (alert.pid && alert.pid > 0) {
                  onConfirm?.(alert.pid);
                  onClose();
                }
              }}
              className="px-3 py-1.5 rounded-lg bg-red-600/20 hover:bg-red-600/30 text-red-300 border border-red-500/30 text-xs font-semibold flex items-center space-x-1.5 transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
            >
              <X className="w-3.5 h-3.5" />
              <span>Confirm & Kill</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
