/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        shield: {
          dark: '#0b0f17',
          card: '#121824',
          border: '#1f293d',
          accent: '#3b82f6',
          danger: '#ef4444',
          warning: '#f59e0b',
          success: '#10b981',
          text: '#f3f4f6',
          muted: '#9ca3af',
        }
      }
    },
  },
  plugins: [],
}
