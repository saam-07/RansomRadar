import { ChevronRight, ShieldAlert } from 'lucide-react';
import { AlertItem } from '../../types/api';

interface AlertFeedProps {
  alerts: AlertItem[];
  onSelectAlert: (alert: AlertItem) => void;
}

export const AlertFeed: React.FC<AlertFeedProps> = ({ alerts, onSelectAlert }) => {
  return (
    <div className="bg-[#0d1424] border border-slate-800 rounded-xl overflow-hidden flex flex-col h-full">
      <div className="p-5 border-b border-slate-800 flex items-center justify-between">
        <div>
          <h3 className="text-sm font-semibold uppercase tracking-wider text-slate-200">
            Forensic Alert Feed
          </h3>
          <p className="text-xs text-slate-400 mt-0.5">
            Real-time containment incidents and behavioral attribution alerts
          </p>
        </div>
        <div className="text-xs font-mono px-2 py-0.5 rounded bg-red-500/10 text-red-400 border border-red-500/20">
          {alerts.length} Incidents
        </div>
      </div>

      <div className="divide-y divide-slate-800/60 overflow-y-auto max-h-96">
        {alerts.length === 0 ? (
          <div className="p-8 text-center text-slate-400 text-xs italic">
            No active threat alerts. Clean system baseline telemetry.
          </div>
        ) : (
          alerts.map((alert) => {
            const timeStr = new Date(alert.timestamp).toLocaleTimeString();
            const summary = alert.explanation?.summary || 'Ransomware behavioral threshold crossed.';

            return (
              <div
                key={alert.id}
                onClick={() => onSelectAlert(alert)}
                className="p-4 hover:bg-slate-800/30 transition-colors cursor-pointer flex items-center justify-between group"
              >
                <div className="flex items-start space-x-3">
                  <div className="p-2 rounded-lg bg-red-500/10 text-red-400 border border-red-500/20 mt-0.5">
                    <ShieldAlert className="w-4 h-4" />
                  </div>
                  <div>
                    <div className="flex items-center space-x-2">
                      <span className="text-xs font-bold text-white font-mono">
                        PID {alert.pid} ({alert.process_name})
                      </span>
                      <span className="px-1.5 py-0.2 rounded text-[10px] uppercase font-mono bg-red-500/20 text-red-400 border border-red-500/40">
                        {alert.risk_level}
                      </span>
                      <span className="text-[10px] text-slate-400 font-mono">{timeStr}</span>
                    </div>
                    <p className="text-xs text-slate-400 mt-1 line-clamp-1 group-hover:text-slate-300">
                      {summary}
                    </p>
                    <div className="flex items-center space-x-3 mt-1.5 text-[10px] font-mono text-slate-400">
                      <span>EWMA: <strong className="text-red-400">{alert.ewma_score.toFixed(3)}</strong></span>
                      <span>Detector: <strong className="text-emerald-400">{alert.model_name}</strong></span>
                      <span>Action: <strong className="text-amber-400">{alert.action_taken}</strong></span>
                    </div>
                  </div>
                </div>

                <div className="text-slate-400 group-hover:text-blue-400 transition-colors p-1">
                  <ChevronRight className="w-4 h-4" />
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};
