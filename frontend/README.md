# Frontend - CyberSec AI Assistant

React.js frontend with Tailwind CSS for the CyberSec AI Assistant vulnerability scanning platform.

## 🚀 Quick Start

### Development Mode

```bash
# Install dependencies
npm install

# Start dev server
npm run dev
```

The dev server will start on http://localhost:5173 (or next available port).

### Production Build

```bash
# Build for production
npm run build

# Preview production build
npm run preview
```

## 📁 Project Structure

```
frontend/
├── src/
│   ├── components/      # React components
│   │   ├── ScanForm.jsx
│   │   ├── Statistics.jsx
│   │   ├── RecentScans.jsx
│   │   └── ScanResults.jsx
│   ├── services/        # API service layer
│   │   └── api.js
│   ├── App.jsx          # Main app component
│   ├── main.jsx         # Entry point
│   └── index.css        # Tailwind CSS
├── index.html
├── package.json
├── vite.config.js
└── tailwind.config.js
```

## 🎨 Features

- **React 18** with modern hooks
- **Tailwind CSS** for styling
- **Vite** for fast development
- **Axios** for API calls
- **Lucide React** for icons
- **Responsive design**

## 🔧 Configuration

### Environment Variables

Create a `.env` file:

```env
VITE_API_URL=http://localhost:8000
```

### Vite Configuration

Edit `vite.config.js` to customize:
- Dev server port
- API proxy settings
- Build options

## 📦 Dependencies

### Production
- `react` - UI library
- `react-dom` - React DOM renderer
- `axios` - HTTP client
- `lucide-react` - Icon library

### Development
- `vite` - Build tool
- `tailwindcss` - CSS framework
- `eslint` - Linting

## 🛠️ Available Scripts

- `npm run dev` - Start development server
- `npm run build` - Build for production
- `npm run preview` - Preview production build
- `npm run lint` - Run ESLint

## 📝 Notes

- The frontend is automatically built and served by the backend in production
- For development, use `npm run dev` and configure proxy in `vite.config.js`
- API calls are handled by `src/services/api.js`

