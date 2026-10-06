import { Cpu, AlertOctagon, Lock, ShieldCheck } from 'lucide-react';
import { ProcessItem, AlertItem } from '../../types/api';

interface KpiCardsProps {
  processes: ProcessItem[];
  alerts: AlertItem[];
  filesSummary?: { intact: number; restored: number; encrypted: number };
}

export const KpiCards: React.FC<KpiCardsProps> = ({
  processes,
  alerts,
  filesSummary = { intact: 300, restored: 0, encrypted: 0 },
}) => {
  const activeProcessesCount = processes.length;
  const criticalAlertsCount = alerts.filter((a) => a.risk_level === 'CRITICAL' && a.status === 'active').length;
  const containedCount = processes.filter((p) => p.is_frozen || p.status === 'frozen' || p.status === 'quarantined').length;
  const totalProtectedFiles = filesSummary.intact + filesSummary.restored;

  const cards = [
    {
      title: 'Monitored Processes',
      value: activeProcessesCount,
      subtext: `${processes.filter((p) => p.risk_level === 'NORMAL').length} operating normally`,
      icon: Cpu,
      color: 'text-blue-400',
      bgColor: 'bg-blue-500/10 border-blue-500/20',
    },
    {
      title: 'Active Alerts',
      value: criticalAlertsCount,
      subtext: `${alerts.length} total forensic detections`,
      icon: AlertOctagon,
      color: criticalAlertsCount > 0 ? 'text-red-400' : 'text-slate-400',
      bgColor: criticalAlertsCount > 0 ? 'bg-red-500/10 border-red-500/20' : 'bg-slate-800/40 border-slate-700/30',
    },
    {
      title: 'Contained Threats',
      value: containedCount,
      subtext: `${processes.filter((p) => p.status === 'killed').length} terminated`,
      icon: Lock,
      color: containedCount > 0 ? 'text-amber-400' : 'text-slate-400',
      bgColor: containedCount > 0 ? 'bg-amber-500/10 border-amber-500/20' : 'bg-slate-800/40 border-slate-700/30',
    },
    {
      title: 'Files Protected / Restored',
      value: `${totalProtectedFiles} / ${filesSummary.restored}`,
      subtext: filesSummary.encrypted > 0 ? `${filesSummary.encrypted} modified pending review` : '0 files compromised',
      icon: ShieldCheck,
      color: 'text-emerald-400',
      bgColor: 'bg-emerald-500/10 border-emerald-500/20',
    },
  ];

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
      {cards.map((c, i) => {
        const Icon = c.icon;
        return (
          <div
            key={i}
            className={`p-5 rounded-xl border bg-[#0d1424] flex items-start justify-between transition-all ${c.bgColor}`}
          >
            <div>
              <p className="text-xs font-medium uppercase tracking-wider text-slate-400">
                {c.title}
              </p>
              <h3 className="text-2xl font-bold text-white mt-1.5 font-mono">
                {c.value}
              </h3>
              <p className="text-xs text-slate-400 mt-1">
                {c.subtext}
              </p>
            </div>
            <div className={`p-2 rounded-lg bg-slate-900 border border-slate-800 ${c.color}`}>
              <Icon className="w-5 h-5" />
            </div>
          </div>
        );
      })}
    </div>
  );
};
