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
    <div className="fixed inset-0 z-50 flex justify-end bg-[#2c2436]/40 backdrop-blur-sm animate-fadeIn">
      <div className="w-full max-w-xl bg-[#fcfaf8] border-l border-[#e5dbe8] h-full overflow-y-auto flex flex-col justify-between shadow-2xl p-6 text-[#2c2436]">
        {/* Header */}
        <div>
          <div className="flex items-center justify-between border-b border-[#ebdfe9] pb-4">
            <div className="flex items-center space-x-3">
              <div className="p-2 rounded-lg bg-[#fdecee] text-[#9e3146] border border-[#f8c4cd]">
                <ShieldAlert className="w-5 h-5" />
              </div>
              <div>
                <h2 className="text-base font-bold text-[#2c2436] flex items-center space-x-2">
                  <span>Forensic Alert Evidence</span>
                  <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-[#fdecee] text-[#9e3146] border border-[#f8c4cd]">
                    CRITICAL
                  </span>
                </h2>
                <p className="text-xs text-[#786c85] font-mono mt-0.5">
                  ID: {alert.id.slice(0, 8)}... | PID {alert.pid} ({alert.process_name})
                </p>
              </div>
            </div>

            <button
              onClick={onClose}
              className="p-1.5 rounded-lg text-[#786c85] hover:text-[#2c2436] hover:bg-[#f3edf6] transition-colors"
            >
              <X className="w-5 h-5" />
            </button>
          </div>

          {/* Forensic Narrative */}
          <div className="my-5 p-4 rounded-lg bg-[#fef7f6] border border-[#f7d6dc]">
            <div className="flex items-center space-x-2 text-xs font-semibold text-[#9e3146] uppercase tracking-wider mb-1.5">
              <AlertOctagon className="w-4 h-4" />
              <span>Attribution Summary</span>
            </div>
            <p className="text-xs text-[#4a4055] leading-relaxed font-sans">
              {expl.summary || 'Anomalous behavioral rates and byte entropy triggered critical containment.'}
            </p>
            <div className="flex items-center space-x-4 mt-3 text-[11px] font-mono text-[#786c85]">
              <div>Engine: <span className="text-[#246e40] font-bold">{alert.model_name || 'Behavioral Core'}</span></div>
              <div>Risk Score: <span className="text-[#9e3146] font-bold">{alert.ewma_score.toFixed(4)}</span></div>
              <div>Action: <span className="text-[#9b5825] font-bold">{alert.action_taken}</span></div>
            </div>
          </div>

          {/* Feature Contributions Breakdown */}
          <div className="space-y-3 mb-6">
            <h4 className="text-xs font-semibold uppercase tracking-wider text-[#786c85] flex items-center justify-between">
              <span>Behavioral Feature Attribution</span>
              <span className="text-[11px] font-normal text-[#786c85]">Behavioral Attribution Matrix</span>
            </h4>

            {contributions.length === 0 ? (
              <p className="text-xs text-[#8c7f99] italic">No detailed breakdown available for this alert.</p>
            ) : (
              <div className="space-y-2">
                {contributions.map((c, idx) => (
                  <div
                    key={idx}
                    className="p-3 rounded-lg bg-white border border-[#ebdfe9] space-y-1.5 shadow-xs"
                  >
                    <div className="flex items-center justify-between text-xs">
                      <span className="font-mono font-semibold text-[#5b82a6]">{c.feature}</span>
                      <span className="font-mono text-[#2c2436]">
                        Value: {typeof c.value === 'number' ? c.value.toFixed(2) : c.value}
                      </span>
                    </div>
                    {c.narrative && (
                      <p className="text-[11px] text-[#62566e] font-sans">{c.narrative}</p>
                    )}
                    {c.contribution_score !== undefined && (
                      <div className="flex items-center space-x-2 pt-1">
                        <span className="text-[10px] text-[#786c85] font-mono">Impact Score:</span>
                        <div className="h-1.5 flex-1 bg-[#ede5ee] rounded-full overflow-hidden">
                          <div
                            className="h-full bg-[#b54a5f] rounded-full"
                            style={{ width: `${Math.min(100, Math.round(c.contribution_score * 100))}%` }}
                          />
                        </div>
                        <span className="text-[10px] font-mono text-[#9e3146]">
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
            <h4 className="text-xs font-semibold uppercase tracking-wider text-[#786c85] flex items-center space-x-2">
              <Terminal className="w-3.5 h-3.5" />
              <span>Observed Window Feature Vector</span>
            </h4>
            <div className="p-3 rounded-lg bg-[#fbf7f9] border border-[#ebdfe9] font-mono text-[11px] text-[#554a62] max-h-48 overflow-y-auto">
              <pre>{JSON.stringify(alert.window_data, null, 2)}</pre>
            </div>
          </div>
        </div>

        {/* Footer Actions */}
        <div className="border-t border-[#ebdfe9] pt-4 flex items-center justify-between mt-6">
          <div className="text-xs text-[#786c85]">
            Status: <span className="uppercase font-mono text-[#2c2436] font-semibold">{alert.status}</span>
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
              className="px-3 py-1.5 rounded-lg bg-[#e7f4ed] hover:bg-[#d6ede0] text-[#236b3e] border border-[#bfe4cd] text-xs font-semibold flex items-center space-x-1.5 transition-colors disabled:opacity-40 disabled:cursor-not-allowed shadow-xs"
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
              className="px-3 py-1.5 rounded-lg bg-[#fdecee] hover:bg-[#fbdde1] text-[#9e3146] border border-[#f7c0ca] text-xs font-semibold flex items-center space-x-1.5 transition-colors disabled:opacity-40 disabled:cursor-not-allowed shadow-xs"
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
