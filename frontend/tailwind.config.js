/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{vue,js,ts,jsx,tsx}"
  ],
  theme: {
    extend: {
      colors: {
        primary: '#0A84FF',
        secondary: '#FF9500',
        dark: '#1C1C1E',
        light: '#F2F2F7',
      },
      animation: {
        'spin-slow': 'spin 60s linear infinite',
      },
      boxShadow: {
        'gradient-to-r': 'linear-gradient(to right, #1f2937, #111827)',
      }
    },
  },
  plugins: [],
}

