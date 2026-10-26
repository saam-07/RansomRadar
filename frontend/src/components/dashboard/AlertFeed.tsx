import { ChevronRight, ShieldAlert } from 'lucide-react';
import { AlertItem } from '../../types/api';

interface AlertFeedProps {
  alerts: AlertItem[];
  onSelectAlert: (alert: AlertItem) => void;
}

export const AlertFeed: React.FC<AlertFeedProps> = ({ alerts, onSelectAlert }) => {
  return (
    <div className="bg-white/85 border border-[#e5dbe8] rounded-2xl overflow-hidden flex flex-col h-full shadow-xs">
      <div className="p-6 border-b border-[#ebdfe9] flex items-center justify-between">
        <div>
          <h3 className="text-sm font-semibold uppercase tracking-wider text-[#2c2436]">
            Forensic Alert Feed
          </h3>
          <p className="text-xs text-[#786c85] mt-1">
            Real-time containment incidents and behavioral attribution alerts
          </p>
        </div>
        <span className="text-xs font-mono font-medium text-[#9e3146]">
          {alerts.length} Incidents
        </span>
      </div>

      <div className="divide-y divide-[#ebdfe9] overflow-y-auto max-h-96">
        {alerts.length === 0 ? (
          <div className="p-8 text-center text-[#8c7f99] text-xs italic">
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
                className="p-4 hover:bg-[#fbf7f9]/80 transition-colors cursor-pointer flex items-center justify-between group"
              >
                <div className="flex items-start space-x-3">
                  <div className="p-2 rounded-lg bg-[#fdecee] text-[#9e3146] border border-[#f8c4cd] mt-0.5">
                    <ShieldAlert className="w-4 h-4" />
                  </div>
                  <div>
                    <div className="flex items-center space-x-2">
                      <span className="text-xs font-bold text-[#2c2436] font-mono">
                        PID {alert.pid || '—'} {alert.process_name ? `(${alert.process_name})` : ''}
                      </span>
                      <span className="px-1.5 py-0.2 rounded text-[10px] uppercase font-mono bg-[#fdecee] text-[#9e3146] border border-[#f8c4cd]">
                        {alert.risk_level}
                      </span>
                      <span className="text-[10px] text-[#8c7f99] font-mono">{timeStr}</span>
                    </div>
                    <p className="text-xs text-[#62566e] mt-1 line-clamp-1 group-hover:text-[#2c2436]">
                      {summary}
                    </p>
                    <div className="flex items-center space-x-3 mt-1.5 text-[10px] font-mono text-[#786c85]">
                      <span>Risk: <strong className="text-[#9e3146]">{Number(alert.ewma_score || 0).toFixed(3)}</strong></span>
                      <span>Engine: <strong className="text-[#246e40]">{alert.model_name || 'Behavioral Core'}</strong></span>
                      <span>Action: <strong className="text-[#9b5825]">{alert.action_taken}</strong></span>
                    </div>
                  </div>
                </div>

                <div className="text-[#9b8fa7] group-hover:text-[#b56576] transition-colors p-1">
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
