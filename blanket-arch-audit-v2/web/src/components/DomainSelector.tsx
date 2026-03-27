"use client";

interface Domain {
  id: string;
  label: string;
  icon: string;
  frameworks: string[];
}

export default function DomainSelector({
  domains, selected, onSelect,
}: {
  domains: Domain[];
  selected: string;
  onSelect: (id: string) => void;
}) {
  return (
    <div className="flex gap-3 flex-wrap">
      {domains.map((d) => (
        <button
          key={d.id}
          onClick={() => onSelect(d.id)}
          className={`px-4 py-2 rounded-lg border transition-all text-sm font-medium ${
            selected === d.id
              ? "border-accent bg-accent/10 text-accent"
              : "border-dark-border bg-dark-card text-gray-400 hover:border-accent/50"
          }`}
        >
          <span className="mr-1">{d.icon}</span> {d.label}
        </button>
      ))}
    </div>
  );
}
