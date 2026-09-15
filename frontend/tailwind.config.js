/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        // Single restrained accent used for links, active states and focus.
        accent: {
          DEFAULT: "#2563eb",
          muted: "#3b82f6",
          deep: "#1d4ed8",
        },
        // Kept as an alias so existing `brand` utilities resolve to the accent.
        brand: {
          DEFAULT: "#2563eb",
          muted: "#3b82f6",
          deep: "#1d4ed8",
        },
      },
      fontFamily: {
        sans: ["Inter", "ui-sans-serif", "system-ui", "sans-serif"],
        mono: ["JetBrains Mono", "ui-monospace", "SFMono-Regular", "monospace"],
      },
      boxShadow: {
        card: "0 1px 2px 0 rgba(16, 24, 40, 0.04), 0 1px 3px 0 rgba(16, 24, 40, 0.06)",
        "card-hover": "0 4px 12px -2px rgba(16, 24, 40, 0.10), 0 2px 6px -2px rgba(16, 24, 40, 0.06)",
      },
      backgroundImage: {
        "brand-gradient": "linear-gradient(135deg, #3b82f6 0%, #2563eb 100%)",
        "grid-faint":
          "linear-gradient(to right, rgba(15,23,42,0.05) 1px, transparent 1px), linear-gradient(to bottom, rgba(15,23,42,0.05) 1px, transparent 1px)",
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
