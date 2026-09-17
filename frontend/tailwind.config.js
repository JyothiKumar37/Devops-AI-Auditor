/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        // Primary product identity: a deep indigo→violet family used for the
        // brand mark, primary actions, active nav and focus rings.
        brand: {
          50: "#eef2ff",
          100: "#e0e7ff",
          200: "#c7d2fe",
          300: "#a5b4fc",
          400: "#818cf8",
          500: "#6366f1",
          DEFAULT: "#4f46e5",
          muted: "#6366f1",
          deep: "#4338ca",
          violet: "#7c3aed",
        },
        accent: {
          DEFAULT: "#4f46e5",
          muted: "#6366f1",
          deep: "#4338ca",
        },
      },
      fontFamily: {
        sans: ["Inter", "ui-sans-serif", "system-ui", "sans-serif"],
        mono: ["JetBrains Mono", "ui-monospace", "SFMono-Regular", "monospace"],
      },
      boxShadow: {
        card: "0 1px 2px 0 rgba(16, 24, 40, 0.05)",
        "card-hover": "0 2px 6px -1px rgba(16, 24, 40, 0.08)",
        soft: "0 1px 3px rgba(16,24,40,0.04), 0 1px 2px rgba(16,24,40,0.04)",
        elevated:
          "0 10px 30px -12px rgba(30,27,75,0.18), 0 4px 12px -6px rgba(30,27,75,0.10)",
        glow: "0 12px 40px -12px rgba(79,70,229,0.45)",
        "inner-line": "inset 0 -1px 0 0 rgba(15,23,42,0.06)",
      },
      backgroundImage: {
        "brand-gradient": "linear-gradient(135deg, #4f46e5 0%, #7c3aed 100%)",
        "brand-sheen": "linear-gradient(135deg, #6366f1 0%, #8b5cf6 55%, #a855f7 100%)",
      },
      keyframes: {
        "fade-rise": {
          "0%": { opacity: "0", transform: "translateY(6px)" },
          "100%": { opacity: "1", transform: "translateY(0)" },
        },
        shimmer: {
          "100%": { transform: "translateX(100%)" },
        },
        "pulse-ring": {
          "0%": { boxShadow: "0 0 0 0 rgba(16,185,129,0.4)" },
          "70%": { boxShadow: "0 0 0 6px rgba(16,185,129,0)" },
          "100%": { boxShadow: "0 0 0 0 rgba(16,185,129,0)" },
        },
      },
      animation: {
        "fade-rise": "fade-rise 0.28s ease-out both",
        "pulse-ring": "pulse-ring 2s cubic-bezier(0.4,0,0.6,1) infinite",
      },
    },
  },
  plugins: [],
};
