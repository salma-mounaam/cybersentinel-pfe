// tailwind.config.js
/** @type {import('tailwindcss').Config} */
module.exports = {
  darkMode: ["class"],
  content: [
    "./src/**/*.{ts,tsx,js,jsx}",
  ],
  theme: {
    extend: {
      colors: {
        "cyber-green":  "#22c55e",
        "cyber-violet": "#8b5cf6",
        "cyber-orange": "#f97316",
        "cyber-red":    "#ef4444",
        "cyber-border": "rgba(255,255,255,0.08)",
      },
    },
  },
  plugins: [],
}