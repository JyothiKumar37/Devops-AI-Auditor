/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        surface: {
          DEFAULT: "#0b1120",
          soft: "#0f172a",
          softer: "#1e293b",
        },
        brand: {
          DEFAULT: "#38bdf8",
          muted: "#0ea5e9",
          deep: "#6366f1",
        },
      },
      fontFamily: {
        sans: ["Inter", "ui-sans-serif", "system-ui", "sans-serif"],
        mono: ["JetBrains Mono", "ui-monospace", "SFMono-Regular", "monospace"],
      },
      boxShadow: {
        card: "0 1px 0 0 rgba(255,255,255,0.05) inset, 0 20px 40px -24px rgba(2,6,23,0.9)",
        glow: "0 0 0 1px rgba(56,189,248,0.25), 0 8px 40px -8px rgba(56,189,248,0.35)",
      },
      backgroundImage: {
        "brand-gradient": "linear-gradient(135deg, #38bdf8 0%, #6366f1 100%)",
        "grid-faint":
          "linear-gradient(to right, rgba(148,163,184,0.06) 1px, transparent 1px), linear-gradient(to bottom, rgba(148,163,184,0.06) 1px, transparent 1px)",
      },
      keyframes: {
        "fade-rise": {
          "0%": { opacity: "0", transform: "translateY(8px)" },
          "100%": { opacity: "1", transform: "translateY(0)" },
        },
        shimmer: {
          "0%": { backgroundPosition: "-200% 0" },
          "100%": { backgroundPosition: "200% 0" },
        },
      },
      animation: {
        "fade-rise": "fade-rise 0.4s cubic-bezier(0.16, 1, 0.3, 1) both",
        shimmer: "shimmer 1.6s linear infinite",
      },
    },
  },
  plugins: [],
};
