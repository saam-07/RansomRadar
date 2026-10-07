import {
  Activity,
  PlayCircle,
  BarChart3,
  Database,
  Cpu,
  ShieldAlert,
  Settings,
} from 'lucide-react';

export type NavTab =
  | 'dashboard'
  | 'scenarios'
  | 'comparison'
  | 'datasets'
  | 'models'
  | 'alerts'
  | 'settings';

interface SidebarProps {
  currentTab: NavTab;
  onSelectTab: (tab: NavTab) => void;
  unresolvedAlertsCount?: number;
}

export const Sidebar: React.FC<SidebarProps> = ({
  currentTab,
  onSelectTab,
  unresolvedAlertsCount = 0,
}) => {
  const navItems = [
    { id: 'dashboard' as NavTab, label: 'Live Dashboard', icon: Activity, badge: null },
    { id: 'scenarios' as NavTab, label: 'Scenario Runner', icon: PlayCircle, badge: null },
    { id: 'comparison' as NavTab, label: 'Detection Analysis', icon: BarChart3, badge: null },
    { id: 'datasets' as NavTab, label: 'Event Explorer', icon: Database, badge: null },
    { id: 'models' as NavTab, label: 'Models & Training', icon: Cpu, badge: null },
    {
      id: 'alerts' as NavTab,
      label: 'Alerts & Forensics',
      icon: ShieldAlert,
      badge: unresolvedAlertsCount > 0 ? String(unresolvedAlertsCount) : null,
      badgeColor: 'bg-red-500/20 text-red-400 border border-red-500/30',
    },
    { id: 'settings' as NavTab, label: 'System Settings', icon: Settings, badge: null },
  ];

  return (
    <aside className="w-64 border-r border-slate-800 bg-[#0a0f1d] flex flex-col justify-between select-none shrink-0 transition-all duration-200">
      <div className="py-6 px-4 space-y-1">
        <div className="px-3 pb-3 text-xs font-semibold uppercase tracking-wider text-slate-400">
          Navigation
        </div>

        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = currentTab === item.id;
          return (
            <button
              key={item.id}
              onClick={() => onSelectTab(item.id)}
              className={`w-full flex items-center justify-between px-3 py-2.5 rounded-lg text-sm font-medium transition-colors ${
                isActive
                  ? 'bg-blue-600/15 text-blue-400 border border-blue-500/30 font-semibold'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
              }`}
            >
              <div className="flex items-center space-x-3">
                <Icon className={`w-4 h-4 ${isActive ? 'text-blue-400' : 'text-slate-400'}`} />
                <span>{item.label}</span>
              </div>
              {item.badge && (
                <span
                  className={`text-[10px] font-mono px-1.5 py-0.5 rounded ${
                    item.badgeColor || 'bg-slate-800 text-slate-400 border border-slate-700'
                  }`}
                >
                  {item.badge}
                </span>
              )}
            </button>
          );
        })}
      </div>
    </aside>
  );
};
