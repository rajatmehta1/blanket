"use client";

import { useState } from "react";

export default function RepoInput({
  repos, onChange,
}: {
  repos: string[];
  onChange: (repos: string[]) => void;
}) {
  const [input, setInput] = useState("");

  const addRepo = () => {
    const trimmed = input.trim();
    if (trimmed && !repos.includes(trimmed)) {
      onChange([...repos, trimmed]);
      setInput("");
    }
  };

  const removeRepo = (idx: number) => {
    onChange(repos.filter((_, i) => i !== idx));
  };

  return (
    <div>
      <div className="flex gap-2">
        <input
          type="text"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && addRepo()}
          placeholder="github.com/org/repo or /path/to/local"
          className="flex-1 px-4 py-2 bg-dark-card border border-dark-border rounded-lg
                     text-gray-200 font-mono text-sm placeholder-gray-600
                     focus:border-accent focus:outline-none"
        />
        <button
          onClick={addRepo}
          className="px-4 py-2 bg-accent/10 border border-accent/30 rounded-lg
                     text-accent font-medium text-sm hover:bg-accent/20 transition"
        >
          Add
        </button>
      </div>
      {repos.length > 0 && (
        <div className="mt-3 flex flex-wrap gap-2">
          {repos.map((r, i) => (
            <span
              key={i}
              className="inline-flex items-center gap-1 px-3 py-1 bg-dark-card
                         border border-dark-border rounded-full text-xs font-mono text-gray-300"
            >
              {r.length > 40 ? `...${r.slice(-37)}` : r}
              <button
                onClick={() => removeRepo(i)}
                className="ml-1 text-gray-500 hover:text-red-400"
              >
                ×
              </button>
            </span>
          ))}
        </div>
      )}
    </div>
  );
}
