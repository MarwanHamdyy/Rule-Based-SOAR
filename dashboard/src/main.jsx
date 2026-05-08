import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App.jsx'
import './index.css'
import { SOARProvider } from './context/SOARContext.jsx'

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <SOARProvider>
      <App />
    </SOARProvider>
  </React.StrictMode>,
)
