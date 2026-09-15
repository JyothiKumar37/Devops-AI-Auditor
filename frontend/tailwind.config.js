/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        // Primary brand: a rich indigo→violet family used for gradients,
        // active states, focus rings and key call-to-action surfaces.
        brand: {
          DEFAULT: "#4f46e5",
          muted: "#6366f1",
          deep: "#4338ca",
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
        card: "0 1px 2px 0 rgba(16, 24, 40, 0.04), 0 1px 3px 0 rgba(16, 24, 40, 0.06)",
        "card-hover": "0 10px 24px -6px rgba(16, 24, 40, 0.12), 0 4px 10px -4px rgba(16, 24, 40, 0.07)",
        brand: "0 10px 26px -10px rgba(79, 70, 229, 0.55)",
        "brand-lg": "0 22px 48px -18px rgba(79, 70, 229, 0.55)",
      },
      backgroundImage: {
        "brand-gradient": "linear-gradient(135deg, #4f46e5 0%, #7c3aed 100%)",
        "hero-gradient":
          "linear-gradient(120deg, #4338ca 0%, #6d28d9 48%, #7c3aed 100%)",
        "grid-faint":
          "linear-gradient(to right, rgba(255,255,255,0.10) 1px, transparent 1px), linear-gradient(to bottom, rgba(255,255,255,0.10) 1px, transparent 1px)",
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
