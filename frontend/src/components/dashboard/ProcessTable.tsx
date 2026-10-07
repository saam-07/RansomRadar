import { Check, X, Cpu } from 'lucide-react';
import { ProcessItem } from '../../types/api';

interface ProcessTableProps {
  processes: ProcessItem[];
  policy?: string;
  onRelease?: (pid: number) => void;
  onConfirm?: (pid: number) => void;
}

export const ProcessTable: React.FC<ProcessTableProps> = ({
  processes,
  policy = 'immediate',
  onRelease,
  onConfirm,
}) => {
  return (
    <div className="bg-[#0d1424] border border-slate-800 rounded-xl overflow-hidden flex flex-col">
      <div className="p-5 border-b border-slate-800 flex items-center justify-between">
        <div>
          <h3 className="text-sm font-semibold uppercase tracking-wider text-slate-200">
            Monitored Process Table
          </h3>
          <p className="text-xs text-slate-400 mt-0.5">
            Active process monitoring, stateful EWMA risk levels, and manual containment controls
          </p>
        </div>
        <div className="text-xs font-mono px-2.5 py-1 rounded bg-slate-900 border border-slate-800 text-slate-400">
          {processes.length} Processes Tracked
        </div>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs">
          <thead className="bg-[#090e1a] text-slate-400 uppercase font-mono text-[11px] border-b border-slate-800">
            <tr>
              <th className="py-3 px-4">PID</th>
              <th className="py-3 px-4">Process Name</th>
              <th className="py-3 px-4">Label</th>
              <th className="py-3 px-4 w-44">Risk EWMA</th>
              <th className="py-3 px-4">Level</th>
              <th className="py-3 px-4">Status</th>
              <th className="py-3 px-4">Files Touched</th>
              <th className="py-3 px-4 text-right">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60 font-mono">
            {processes.length === 0 ? (
              <tr>
                <td colSpan={8} className="py-10 text-center text-slate-400 font-sans italic">
                  No active processes in pipeline. Start a scenario to observe behavioral containment.
                </td>
              </tr>
            ) : (
              processes.map((proc) => {
                const ewmaVal = Number(proc.ewma || 0);
                const ewmaPct = Math.min(100, Math.round(ewmaVal * 100));

                let barColor = 'bg-emerald-500';
                if (ewmaVal >= 0.85) barColor = 'bg-red-500';
                else if (ewmaVal >= 0.3) barColor = 'bg-amber-500';

                let levelChipClass = 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30';
                if (proc.risk_level === 'CRITICAL') {
                  levelChipClass = 'bg-red-500/15 text-red-400 border-red-500/30 animate-pulse font-bold';
                } else if (proc.risk_level === 'ELEVATED') {
                  levelChipClass = 'bg-amber-500/10 text-amber-400 border-amber-500/30 font-semibold';
                }

                let statusChipClass = 'bg-slate-800 text-slate-300';
                if (proc.status === 'frozen') {
                  statusChipClass = 'bg-blue-500/20 text-blue-300 border border-blue-500/40 font-bold';
                } else if (proc.status === 'killed') {
                  statusChipClass = 'bg-red-500/20 text-red-300 border border-red-500/40';
                } else if (proc.status === 'quarantined') {
                  statusChipClass = 'bg-purple-500/20 text-purple-300 border border-purple-500/40';
                }

                const hasValidPid = Boolean(proc.pid) && proc.pid > 0;
                const canAct = hasValidPid && (proc.is_frozen || proc.status === 'frozen' || policy === 'manual');

                return (
                  <tr key={proc.pid || Math.random()} className="hover:bg-slate-800/30 transition-colors">
                    <td className="py-3 px-4 font-bold text-slate-200">
                      {proc.pid ?? '—'}
                    </td>
                    <td className="py-3 px-4">
                      <div className="flex items-center space-x-2">
                        <Cpu className="w-3.5 h-3.5 text-slate-400" />
                        <span className="font-semibold text-slate-200 font-sans">{proc.process_name}</span>
                      </div>
                      {proc.cmdline && (
                        <div className="text-[10px] text-slate-400 truncate max-w-xs">{proc.cmdline}</div>
                      )}
                    </td>
                    <td className="py-3 px-4">
                      <span className="px-1.5 py-0.5 rounded text-[10px] uppercase font-mono bg-slate-800 text-slate-400">
                        {proc.label}
                      </span>
                    </td>
                    <td className="py-3 px-4">
                      <div className="space-y-1">
                        <div className="flex justify-between items-center text-[11px] gap-2">
                          <span className="font-semibold text-slate-200">{ewmaVal.toFixed(3)}</span>
                          <span className="text-slate-400">{(proc.probability || 0).toFixed(2)} raw</span>
                        </div>
                        <div className="h-1.5 w-full bg-slate-800 rounded-full overflow-hidden">
                          <div
                            className={`h-full ${barColor} transition-all duration-300`}
                            style={{ width: `${ewmaPct}%` }}
                          />
                        </div>
                      </div>
                    </td>
                    <td className="py-3 px-4">
                      <span className={`px-2 py-0.5 rounded text-[10px] border uppercase ${levelChipClass}`}>
                        {proc.risk_level}
                      </span>
                    </td>
                    <td className="py-3 px-4">
                      <span className={`px-2 py-0.5 rounded text-[10px] uppercase ${statusChipClass}`}>
                        {proc.status}
                      </span>
                    </td>
                    <td className="py-3 px-4 font-mono">
                      <div className="text-slate-300">{proc.files_touched} touched</div>
                      {proc.files_encrypted > 0 && (
                        <div className="text-red-400 text-[10px]">{proc.files_encrypted} encrypted</div>
                      )}
                    </td>
                    <td className="py-3 px-4 text-right">
                      {canAct ? (
                        <div className="flex items-center justify-end space-x-1.5">
                          <button
                            onClick={() => proc.pid && onRelease?.(proc.pid)}
                            className="px-2 py-1 rounded bg-emerald-600/20 hover:bg-emerald-600/30 text-emerald-300 border border-emerald-500/30 flex items-center space-x-1 transition-colors"
                            title="Release / unfreeze process"
                          >
                            <Check className="w-3 h-3" />
                            <span>Release</span>
                          </button>
                          <button
                            onClick={() => proc.pid && onConfirm?.(proc.pid)}
                            className="px-2 py-1 rounded bg-red-600/20 hover:bg-red-600/30 text-red-300 border border-red-500/30 flex items-center space-x-1 transition-colors"
                            title="Confirm threat & kill process"
                          >
                            <X className="w-3 h-3" />
                            <span>Confirm</span>
                          </button>
                        </div>
                      ) : (
                        <span className="text-slate-400 text-[11px] font-sans">Active</span>
                      )}
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};
