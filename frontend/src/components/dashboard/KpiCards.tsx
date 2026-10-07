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
      color: 'text-[#3d5c85]',
      bgColor: 'bg-[#edf2f9] border-[#d2def0]',
    },
    {
      title: 'Active Alerts',
      value: criticalAlertsCount,
      subtext: `${alerts.length} total forensic detections`,
      icon: AlertOctagon,
      color: criticalAlertsCount > 0 ? 'text-[#9e3146]' : 'text-[#786c85]',
      bgColor: criticalAlertsCount > 0 ? 'bg-[#fdecee] border-[#f8c4cd]' : 'bg-[#f5edf3] border-[#e5d9e3]',
    },
    {
      title: 'Contained Threats',
      value: containedCount,
      subtext: `${processes.filter((p) => p.status === 'killed').length} terminated`,
      icon: Lock,
      color: containedCount > 0 ? 'text-[#9b5825]' : 'text-[#786c85]',
      bgColor: containedCount > 0 ? 'bg-[#fef5e8] border-[#fcdcb8]' : 'bg-[#f5edf3] border-[#e5d9e3]',
    },
    {
      title: 'Files Protected / Restored',
      value: `${totalProtectedFiles} / ${filesSummary.restored}`,
      subtext: filesSummary.encrypted > 0 ? `${filesSummary.encrypted} modified pending review` : '0 files compromised',
      icon: ShieldCheck,
      color: 'text-[#246e40]',
      bgColor: 'bg-[#e5f5ec] border-[#c0e6cf]',
    },
  ];

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
      {cards.map((c, i) => {
        const Icon = c.icon;
        return (
          <div
            key={i}
            className="p-6 rounded-2xl border border-[#e5dbe8] bg-white/85 backdrop-blur-sm shadow-xs flex items-start justify-between transition-all"
          >
            <div className="space-y-1">
              <p className="text-xs font-semibold uppercase tracking-wider text-[#786c85]">
                {c.title}
              </p>
              <h3 className="text-3xl font-bold text-[#2d2436] font-mono pt-1">
                {c.value}
              </h3>
              <p className="text-xs text-[#786c85] pt-0.5">
                {c.subtext}
              </p>
            </div>
            <div className={`p-2.5 rounded-xl border ${c.bgColor} ${c.color} shrink-0 ml-3`}>
              <Icon className="w-5 h-5" />
            </div>
          </div>
        );
      })}
    </div>
  );
};
