/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        // One restrained interactive accent (links, active state, focus). Used
        // sparingly; everything structural is neutral gray.
        brand: {
          DEFAULT: "#2563eb",
          muted: "#3b82f6",
          deep: "#1d4ed8",
        },
        accent: {
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
        card: "0 1px 2px 0 rgba(16, 24, 40, 0.05)",
        "card-hover": "0 2px 6px -1px rgba(16, 24, 40, 0.08)",
      },
      keyframes: {
        "fade-rise": {
          "0%": { opacity: "0", transform: "translateY(6px)" },
          "100%": { opacity: "1", transform: "translateY(0)" },
        },
      },
      animation: {
        "fade-rise": "fade-rise 0.28s ease-out both",
      },
    },
  },
  plugins: [],
};
