"use client";

export default function ScanButton({
  scanning, onClick,
}: {
  scanning: boolean;
  onClick: () => void;
}) {
  return (
    <button
      onClick={onClick}
      disabled={scanning}
      className={`w-full py-3 rounded-lg font-semibold text-white transition-all ${
        scanning
          ? "bg-accent/30 cursor-wait"
          : "bg-accent hover:bg-accent/80 active:scale-[0.99]"
      }`}
    >
      {scanning ? (
        <span className="flex items-center justify-center gap-2">
          <span className="animate-spin">◌</span> Scanning...
        </span>
      ) : (
        "Run Audit"
      )}
    </button>
  );
}
