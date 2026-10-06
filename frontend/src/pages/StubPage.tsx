import { Construction } from 'lucide-react';

interface StubPageProps {
  title: string;
  promptStage: string;
  description: string;
}

export const StubPage: React.FC<StubPageProps> = ({
  title,
  promptStage,
  description,
}) => {
  return (
    <div className="flex-1 p-8 flex flex-col items-center justify-center text-center">
      <div className="p-4 rounded-2xl bg-blue-500/10 text-blue-400 border border-blue-500/20 mb-4">
        <Construction className="w-8 h-8" />
      </div>

      <h2 className="text-xl font-bold text-white mb-2">{title}</h2>
      <div className="px-3 py-1 rounded-full text-xs font-mono font-semibold bg-slate-800 text-slate-300 border border-slate-700 mb-4">
        Scheduled for {promptStage}
      </div>

      <p className="text-sm text-slate-400 max-w-md leading-relaxed">
        {description}
      </p>
    </div>
  );
};
