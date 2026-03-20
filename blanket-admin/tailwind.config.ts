import type { Config } from 'tailwindcss'

const config: Config = {
  content: [
    './app/**/*.{js,ts,jsx,tsx,mdx}',
    './components/**/*.{js,ts,jsx,tsx,mdx}',
    './lib/**/*.{js,ts,jsx,tsx,mdx}',
    './node_modules/@tremor/**/*.{js,ts,jsx,tsx}',
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        charcoal: '#1a1a2e',
        ember: '#e94560',
        gold: '#f5a623',
        'slate-blue': '#16213e',
        // Tremor color overrides for dark mode
        tremor: {
          brand: {
            faint: '#1a1a2e',
            muted: '#16213e',
            subtle: '#e94560',
            DEFAULT: '#e94560',
            emphasis: '#f5a623',
            inverted: '#ffffff',
          },
          background: {
            muted: '#16213e',
            subtle: '#1a1a2e',
            DEFAULT: '#0f0f23',
            emphasis: '#16213e',
          },
          border: {
            DEFAULT: '#2a2a4a',
          },
          content: {
            subtle: '#6b7280',
            DEFAULT: '#d1d5db',
            emphasis: '#f3f4f6',
            strong: '#ffffff',
            inverted: '#0f0f23',
          },
        },
      },
      fontFamily: {
        sans: ['var(--font-inter)', 'system-ui', 'sans-serif'],
        mono: ['var(--font-jetbrains)', 'monospace'],
      },
      boxShadow: {
        'tremor-input': '0 1px 2px 0 rgb(0 0 0 / 0.05)',
        'tremor-card': '0 1px 3px 0 rgb(0 0 0 / 0.1), 0 1px 2px -1px rgb(0 0 0 / 0.1)',
        'tremor-dropdown': '0 4px 6px -1px rgb(0 0 0 / 0.1), 0 2px 4px -2px rgb(0 0 0 / 0.1)',
      },
      borderRadius: {
        'tremor-small': '0.375rem',
        'tremor-default': '0.5rem',
        'tremor-full': '9999px',
      },
      fontSize: {
        'tremor-label': ['0.75rem', { lineHeight: '1rem' }],
        'tremor-default': ['0.875rem', { lineHeight: '1.25rem' }],
        'tremor-title': ['1.125rem', { lineHeight: '1.75rem' }],
        'tremor-metric': ['1.875rem', { lineHeight: '2.25rem' }],
      },
    },
  },
  plugins: [],
}

export default config
