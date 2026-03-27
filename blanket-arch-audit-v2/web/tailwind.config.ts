import type { Config } from "tailwindcss";

const config: Config = {
  content: ["./src/**/*.{js,ts,jsx,tsx,mdx}"],
  theme: {
    extend: {
      colors: {
        dark: { bg: "#0b0f1a", card: "#111827", border: "#1f2937" },
        accent: "#6C5CE7",
        severity: {
          critical: "#ef4444",
          high: "#f97316",
          medium: "#fbbf24",
          low: "#64748b",
        },
      },
      fontFamily: {
        sans: ["Sora", "sans-serif"],
        mono: ["JetBrains Mono", "monospace"],
      },
    },
  },
  plugins: [],
};
export default config;
