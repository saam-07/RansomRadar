import { Construction } from 'lucide-react';

interface StubPageProps {
  title: string;
  description: string;
}

export const StubPage: React.FC<StubPageProps> = ({
  title,
  description,
}) => {
  return (
    <div className="flex-1 p-8 flex flex-col items-center justify-center text-center">
      <div className="p-4 rounded-2xl bg-[#eddce5] text-[#b56576] border border-[#dcbcd1] mb-4">
        <Construction className="w-8 h-8" />
      </div>

      <h2 className="text-xl font-bold text-[#2c2436] mb-2">{title}</h2>
      <div className="px-3 py-1 rounded-full text-xs font-mono font-semibold bg-[#f2e9f2] text-[#6b5f77] border border-[#e0d3e5] mb-4">
        Will implement in future
      </div>

      <p className="text-sm text-[#786c85] max-w-md leading-relaxed">
        {description}
      </p>
    </div>
  );
};
