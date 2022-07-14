/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./templates/**/*.html"
  ],
  theme: {
    extend: {
      width: {
        '768': '48rem',
        '1024': '64rem'
      }
    },
  },
  plugins: [
    require('@tailwindcss/typography'),
  ],
}
