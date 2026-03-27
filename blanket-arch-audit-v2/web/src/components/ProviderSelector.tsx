"use client";

interface Provider {
  id: string;
  label: string;
  models: string[];
}

export default function ProviderSelector({
  providers, selected, onSelect,
}: {
  providers: Provider[];
  selected: string;
  onSelect: (id: string) => void;
}) {
  const current = providers.find((p) => p.id === selected);
  return (
    <div>
      <div className="flex gap-3 flex-wrap">
        {providers.map((p) => (
          <button
            key={p.id}
            onClick={() => onSelect(p.id)}
            className={`px-4 py-2 rounded-lg border transition-all text-sm ${
              selected === p.id
                ? "border-accent bg-accent/10 text-accent"
                : "border-dark-border bg-dark-card text-gray-400 hover:border-accent/50"
            }`}
          >
            {p.label}
          </button>
        ))}
      </div>
      {current && current.models.length > 0 && (
        <div className="mt-2 text-xs text-gray-500 font-mono">
          Models: {current.models.join(", ")}
        </div>
      )}
    </div>
  );
}
