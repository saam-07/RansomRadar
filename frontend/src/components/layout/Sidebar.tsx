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
      badgeColor: 'bg-[#fdecee] text-[#9e3146] border border-[#f8c4cd]',
    },
    { id: 'settings' as NavTab, label: 'System Settings', icon: Settings, badge: null },
  ];

  return (
    <aside className="w-64 border-r border-[#e5dbe8] bg-[#fbf9fa]/95 backdrop-blur-md flex flex-col justify-between select-none shrink-0 transition-all duration-200 shadow-sm">
      <div className="py-6 px-4 space-y-1">
        <div className="px-3 pb-3 text-xs font-semibold uppercase tracking-wider text-[#786c85]">
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
                  ? 'bg-[#f4e6ec] text-[#8e455d] border border-[#e2c1ce] font-semibold'
                  : 'text-[#5e5369] hover:text-[#2c2436] hover:bg-[#f6eff4]'
              }`}
            >
              <div className="flex items-center space-x-3">
                <Icon className={`w-4 h-4 ${isActive ? 'text-[#8e455d]' : 'text-[#786c85]'}`} />
                <span>{item.label}</span>
              </div>
              {item.badge && (
                <span
                  className={`text-[10px] font-mono px-1.5 py-0.5 rounded ${
                    item.badgeColor || 'bg-[#f1ebf4] text-[#6b5f77] border border-[#ded5e3]'
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
