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
    <div className="bg-white/85 border border-[#e5dbe8] rounded-xl overflow-hidden flex flex-col shadow-sm">
      <div className="p-5 border-b border-[#ebdfe9] flex items-center justify-between">
        <div>
          <h3 className="text-sm font-semibold uppercase tracking-wider text-[#2c2436]">
            Monitored Process Table
          </h3>
          <p className="text-xs text-[#786c85] mt-0.5">
            Active process monitoring, behavioral risk scoring, and manual containment controls
          </p>
        </div>
        <div className="text-xs font-mono px-2.5 py-1 rounded bg-[#f5edf4] border border-[#e3d7e2] text-[#695d73]">
          {processes.length} Processes Tracked
        </div>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs">
          <thead className="bg-[#fbf7f9] text-[#71647e] uppercase font-mono text-[11px] border-b border-[#ebdfe9]">
            <tr>
              <th className="py-3 px-4">PID</th>
              <th className="py-3 px-4">Process Name</th>
              <th className="py-3 px-4">Label</th>
              <th className="py-3 px-4 w-44">Risk Score</th>
              <th className="py-3 px-4">Level</th>
              <th className="py-3 px-4">Status</th>
              <th className="py-3 px-4">Files Touched</th>
              <th className="py-3 px-4 text-right">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[#ebdfe9] font-mono">
            {processes.length === 0 ? (
              <tr>
                <td colSpan={8} className="py-10 text-center text-[#8c7f99] font-sans italic">
                  No active processes in pipeline. Start a scenario to observe behavioral containment.
                </td>
              </tr>
            ) : (
              processes.map((proc) => {
                const ewmaVal = Number(proc.ewma || 0);
                const ewmaPct = Math.min(100, Math.round(ewmaVal * 100));

                let barColor = 'bg-[#5b9e75]';
                if (ewmaVal >= 0.85) barColor = 'bg-[#b54a5f]';
                else if (ewmaVal >= 0.3) barColor = 'bg-[#d97736]';

                let levelChipClass = 'bg-[#e5f5ec] text-[#246e40] border-[#c0e6cf]';
                if (proc.risk_level === 'CRITICAL') {
                  levelChipClass = 'bg-[#fdecee] text-[#9e3146] border-[#f8c4cd] animate-pulse font-bold';
                } else if (proc.risk_level === 'ELEVATED') {
                  levelChipClass = 'bg-[#fef5e8] text-[#9b5825] border-[#fcdcb8] font-semibold';
                }

                let statusChipClass = 'bg-[#f1ebf4] text-[#6b5f77]';
                if (proc.status === 'frozen') {
                  statusChipClass = 'bg-[#eef1f8] text-[#3d5386] border border-[#d2dbf0] font-bold';
                } else if (proc.status === 'killed') {
                  statusChipClass = 'bg-[#fdecee] text-[#9e3146] border border-[#f8c4cd]';
                } else if (proc.status === 'quarantined') {
                  statusChipClass = 'bg-[#f5eef8] text-[#6e4682] border border-[#e0cbe9]';
                }

                const hasValidPid = Boolean(proc.pid) && proc.pid > 0;
                const canAct = hasValidPid && (proc.is_frozen || proc.status === 'frozen' || policy === 'manual');

                return (
                  <tr key={proc.pid || Math.random()} className="hover:bg-[#fbf7f9]/80 transition-colors">
                    <td className="py-3 px-4 font-bold text-[#2c2436]">
                      {proc.pid ?? '—'}
                    </td>
                    <td className="py-3 px-4">
                      <div className="flex items-center space-x-2">
                        <Cpu className="w-3.5 h-3.5 text-[#7d7189]" />
                        <span className="font-semibold text-[#2c2436] font-sans">{proc.process_name}</span>
                      </div>
                      {proc.cmdline && (
                        <div className="text-[10px] text-[#7e738b] truncate max-w-xs">{proc.cmdline}</div>
                      )}
                    </td>
                    <td className="py-3 px-4">
                      <span className="px-1.5 py-0.5 rounded text-[10px] uppercase font-mono bg-[#f0e8f0] text-[#63556d]">
                        {proc.label}
                      </span>
                    </td>
                    <td className="py-3 px-4">
                      <div className="space-y-1">
                        <div className="flex justify-between items-center text-[11px] gap-2">
                          <span className="font-semibold text-[#2c2436]">{ewmaVal.toFixed(3)}</span>
                          <span className="text-[#786c85]">{(proc.probability || 0).toFixed(2)} score</span>
                        </div>
                        <div className="h-1.5 w-full bg-[#ede5ee] rounded-full overflow-hidden">
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
                      <div className="text-[#4a4055]">{proc.files_touched} touched</div>
                      {proc.files_encrypted > 0 && (
                        <div className="text-[#9e3146] text-[10px]">{proc.files_encrypted} encrypted</div>
                      )}
                    </td>
                    <td className="py-3 px-4 text-right">
                      {canAct ? (
                        <div className="flex items-center justify-end space-x-1.5">
                          <button
                            onClick={() => proc.pid && onRelease?.(proc.pid)}
                            className="px-2 py-1 rounded bg-[#e7f4ed] hover:bg-[#d6ede0] text-[#236b3e] border border-[#bfe4cd] flex items-center space-x-1 transition-colors shadow-xs"
                            title="Release / unfreeze process"
                          >
                            <Check className="w-3 h-3" />
                            <span>Release</span>
                          </button>
                          <button
                            onClick={() => proc.pid && onConfirm?.(proc.pid)}
                            className="px-2 py-1 rounded bg-[#fdecee] hover:bg-[#fbdde1] text-[#9e3146] border border-[#f7c0ca] flex items-center space-x-1 transition-colors shadow-xs"
                            title="Confirm threat & kill process"
                          >
                            <X className="w-3 h-3" />
                            <span>Confirm</span>
                          </button>
                        </div>
                      ) : (
                        <span className="text-[#827690] text-[11px] font-sans">Active</span>
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
