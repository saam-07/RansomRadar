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
    <div className="bg-[#0d1424] border border-slate-800 rounded-xl p-5 flex flex-col space-y-4">
      {/* Top Header & Metrics */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 pb-4">
        <div>
          <h3 className="text-sm font-semibold uppercase tracking-wider text-slate-200 flex items-center space-x-2">
            <span>Virtual Filesystem State</span>
            {isFrozen && (
              <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 flex items-center space-x-1">
                <Snowflake className="w-3 h-3" />
                <span>OVERLAY FROZEN</span>
              </span>
            )}
          </h3>
          <p className="text-xs text-slate-400 mt-0.5">
            Real-time visualization of write encryption damage, cgroup freeze containment, and overlayfs rollback
          </p>
        </div>

        {/* Counter Pills */}
        <div className="flex items-center space-x-2 text-xs font-mono">
          <button
            onClick={() => setFilter('all')}
            className={`px-2.5 py-1 rounded-lg border transition-all ${
              filter === 'all'
                ? 'bg-slate-800 text-white border-slate-600 font-bold'
                : 'bg-slate-900/60 text-slate-400 border-slate-800 hover:text-slate-200'
            }`}
          >
            All ({files.length})
          </button>
          <button
            onClick={() => setFilter('healthy')}
            className={`px-2.5 py-1 rounded-lg border transition-all ${
              filter === 'healthy'
                ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/50 font-bold'
                : 'bg-slate-900/60 text-emerald-400 border-slate-800 hover:border-emerald-500/30'
            }`}
          >
            Intact ({healthyCount})
          </button>
          <button
            onClick={() => setFilter('encrypted')}
            className={`px-2.5 py-1 rounded-lg border transition-all ${
              filter === 'encrypted'
                ? 'bg-red-500/20 text-red-300 border-red-500/50 font-bold'
                : 'bg-slate-900/60 text-red-400 border-slate-800 hover:border-red-500/30'
            }`}
          >
            Encrypted ({encryptedCount})
          </button>
          <button
            onClick={() => setFilter('restored')}
            className={`px-2.5 py-1 rounded-lg border transition-all ${
              filter === 'restored'
                ? 'bg-blue-500/20 text-blue-300 border-blue-500/50 font-bold'
                : 'bg-slate-900/60 text-blue-400 border-slate-800 hover:border-blue-500/30'
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

          let cardStyle = 'bg-slate-900/70 border-slate-800/80 text-slate-300 hover:border-slate-700';
          let statusBadge = (
            <span className="text-[9px] font-mono text-slate-400">Intact</span>
          );

          if (isEncrypted) {
            cardStyle = isFrozen
              ? 'bg-cyan-950/40 border-cyan-500/50 text-cyan-200 animate-pulse'
              : 'bg-red-950/40 border-red-500/60 text-red-200 animate-pulse';
            statusBadge = (
              <span className={`text-[9px] font-mono font-bold flex items-center space-x-0.5 ${isFrozen ? 'text-cyan-400' : 'text-red-400'}`}>
                {isFrozen ? <Snowflake className="w-2.5 h-2.5" /> : <Lock className="w-2.5 h-2.5" />}
                <span>{isFrozen ? 'Frozen' : 'Locked'}</span>
              </span>
            );
          } else if (isRestored) {
            cardStyle = 'bg-emerald-950/30 border-emerald-500/50 text-emerald-200 transition-all duration-500';
            statusBadge = (
              <span className="text-[9px] font-mono font-bold text-emerald-400 flex items-center space-x-0.5">
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
                <Icon className={`w-4 h-4 ${isEncrypted ? 'text-red-400' : isRestored ? 'text-emerald-400' : 'text-slate-400'}`} />
                {statusBadge}
              </div>

              <div className="mt-2">
                <p className="text-[11px] font-mono font-semibold truncate leading-tight">
                  {isEncrypted ? `${displayName}.locked` : displayName}
                </p>
                <p className="text-[9px] text-slate-400 font-mono mt-0.5">
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
