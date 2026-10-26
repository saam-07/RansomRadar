import { useState } from 'react';
import { FileText, Lock, ShieldCheck, Snowflake, FileSpreadsheet, FileCode, Database } from 'lucide-react';

export interface VirtualFileItem {
  id?: string;
  name?: string;
  path?: string;
  file_id?: string;
  size_bytes?: number;
  size_kb?: number;
  status: 'healthy' | 'encrypted' | 'quarantined' | 'restored' | 'frozen';
  encrypted_by_pid?: number | null;
}

interface FilesystemGridProps {
  files: VirtualFileItem[];
  isFrozen?: boolean;
}

export const FilesystemGrid: React.FC<FilesystemGridProps> = ({
  files,
  isFrozen = false,
}) => {
  const [filter, setFilter] = useState<'all' | 'encrypted' | 'restored' | 'healthy'>('all');

  const healthyCount = files.filter((f) => f.status === 'healthy').length;
  const encryptedCount = files.filter((f) => f.status === 'encrypted' || f.status === 'quarantined').length;
  const restoredCount = files.filter((f) => f.status === 'restored').length;

  const filteredFiles = files.filter((f) => {
    if (filter === 'all') return true;
    if (filter === 'healthy') return f.status === 'healthy';
    if (filter === 'encrypted') return f.status === 'encrypted' || f.status === 'quarantined';
    if (filter === 'restored') return f.status === 'restored';
    return true;
  });

  const getFileIcon = (fileName?: string) => {
    if (!fileName) return FileText;
    if (fileName.endsWith('.xlsx') || fileName.endsWith('.csv')) return FileSpreadsheet;
    if (fileName.endsWith('.sql')) return Database;
    if (fileName.endsWith('.py') || fileName.endsWith('.json')) return FileCode;
    return FileText;
  };

  return (
    <div className="bg-white/85 border border-[#e5dbe8] rounded-xl p-5 shadow-sm flex flex-col space-y-4">
      {/* Top Header & Metrics */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[#ebdfe9] pb-4">
        <div>
          <h3 className="text-sm font-semibold uppercase tracking-wider text-[#2c2436] flex items-center space-x-2">
            <span>Virtual Filesystem State</span>
            {isFrozen && (
              <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-[#eef1f8] text-[#3d5386] border border-[#d2dbf0] flex items-center space-x-1 font-bold">
                <Snowflake className="w-3 h-3" />
                <span>OVERLAY FROZEN</span>
              </span>
            )}
          </h3>
          <p className="text-xs text-[#786c85] mt-0.5">
            Real-time visualization of write encryption damage, cgroup freeze containment, and overlayfs rollback
          </p>
        </div>

        {/* Counter Pills */}
        <div className="flex items-center space-x-2 text-xs font-mono">
          <button
            onClick={() => setFilter('all')}
            className={`px-2.5 py-1 rounded-lg border transition-all shadow-xs ${
              filter === 'all'
                ? 'bg-[#f4e6ec] text-[#8e455d] border-[#e2c1ce] font-bold'
                : 'bg-white text-[#786c85] border-[#dfd3e3] hover:text-[#2c2436]'
            }`}
          >
            All ({files.length})
          </button>
          <button
            onClick={() => setFilter('healthy')}
            className={`px-2.5 py-1 rounded-lg border transition-all shadow-xs ${
              filter === 'healthy'
                ? 'bg-[#e5f5ec] text-[#246e40] border-[#c0e6cf] font-bold'
                : 'bg-white text-[#246e40] border-[#dfd3e3] hover:border-[#c0e6cf]'
            }`}
          >
            Intact ({healthyCount})
          </button>
          <button
            onClick={() => setFilter('encrypted')}
            className={`px-2.5 py-1 rounded-lg border transition-all shadow-xs ${
              filter === 'encrypted'
                ? 'bg-[#fdecee] text-[#9e3146] border-[#f8c4cd] font-bold'
                : 'bg-white text-[#9e3146] border-[#dfd3e3] hover:border-[#f8c4cd]'
            }`}
          >
            Encrypted ({encryptedCount})
          </button>
          <button
            onClick={() => setFilter('restored')}
            className={`px-2.5 py-1 rounded-lg border transition-all shadow-xs ${
              filter === 'restored'
                ? 'bg-[#edf2f9] text-[#3d5c85] border-[#d2def0] font-bold'
                : 'bg-white text-[#3d5c85] border-[#dfd3e3] hover:border-[#d2def0]'
            }`}
          >
            Restored ({restoredCount})
          </button>
        </div>
      </div>

      {/* File Grid */}
      <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-6 gap-2.5 max-h-[380px] overflow-y-auto pr-1">
        {filteredFiles.map((f, idx) => {
          const displayName = f.name || (f.path ? f.path.split('/').pop() || f.path : f.id) || f.file_id || `file_${idx}`;
          const displaySize = f.size_bytes !== undefined ? Math.round(f.size_bytes / 1024) : (f.size_kb ?? 0);
          const Icon = getFileIcon(displayName);
          const isEncrypted = f.status === 'encrypted' || f.status === 'quarantined';
          const isRestored = f.status === 'restored';

          let cardStyle = 'bg-white border-[#ebdfe9] text-[#2c2436] hover:border-[#cfbfd3] shadow-xs';
          let statusBadge = (
            <span className="text-[9px] font-mono text-[#786c85]">Intact</span>
          );

          if (isEncrypted) {
            cardStyle = isFrozen
              ? 'bg-[#f0f3fa] border-[#c8d4ec] text-[#2d426d] animate-pulse shadow-xs'
              : 'bg-[#fef0f2] border-[#f8c4cd] text-[#9e3146] animate-pulse shadow-xs';
            statusBadge = (
              <span className={`text-[9px] font-mono font-bold flex items-center space-x-0.5 ${isFrozen ? 'text-[#3d5386]' : 'text-[#9e3146]'}`}>
                {isFrozen ? <Snowflake className="w-2.5 h-2.5" /> : <Lock className="w-2.5 h-2.5" />}
                <span>{isFrozen ? 'Frozen' : 'Locked'}</span>
              </span>
            );
          } else if (isRestored) {
            cardStyle = 'bg-[#eef8f2] border-[#bee3cc] text-[#246e40] transition-all duration-500 shadow-xs';
            statusBadge = (
              <span className="text-[9px] font-mono font-bold text-[#246e40] flex items-center space-x-0.5">
                <ShieldCheck className="w-2.5 h-2.5" />
                <span>Restored</span>
              </span>
            );
          }

          return (
            <div
              key={f.id || f.file_id || `${displayName}_${idx}`}
              className={`p-2.5 rounded-lg border flex flex-col justify-between transition-all duration-300 text-left ${cardStyle}`}
              title={`${displayName} (${displaySize} KB) - ${f.status}`}
            >
              <div className="flex items-start justify-between">
                <Icon className={`w-4 h-4 ${isEncrypted ? 'text-[#9e3146]' : isRestored ? 'text-[#246e40]' : 'text-[#786c85]'}`} />
                {statusBadge}
              </div>

              <div className="mt-2">
                <p className="text-[11px] font-mono font-semibold truncate leading-tight">
                  {isEncrypted ? `${displayName}.locked` : displayName}
                </p>
                <p className="text-[9px] text-[#786c85] font-mono mt-0.5">
                  {displaySize} KB
                </p>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
