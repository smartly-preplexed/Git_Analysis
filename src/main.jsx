import { Component, StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App.jsx'

class BrowserErrorBoundary extends Component {
  constructor(props) {
    super(props)
    this.state = { error: null, recoveryKey: 0 }
  }

  static getDerivedStateFromError(error) {
    return { error }
  }

  componentDidCatch(error, info) {
    console.error('Software Vetter UI error:', error, info)
  }

  render() {
    if (!this.state.error) return <div key={this.state.recoveryKey}>{this.props.children}</div>
    return (
      <main style={{ minHeight: '100vh', padding: '48px', background: '#070b12', color: '#e2e8f0', fontFamily: 'monospace' }}>
        <h1 style={{ color: '#f87171' }}>Software Vetter UI recovered from a browser error</h1>
        <p>The analysis server is independent from this page and may still be running the job.</p>
        <pre style={{ whiteSpace: 'pre-wrap', color: '#94a3b8' }}>{String(this.state.error?.message || this.state.error)}</pre>
        <div style={{ display: 'flex', gap: '10px', marginTop: '20px' }}>
          <button
            type="button"
            onClick={() => this.setState((state) => ({ error: null, recoveryKey: state.recoveryKey + 1 }))}
            style={{ padding: '10px 16px' }}
          >
            Recover WebUI
          </button>
          <button type="button" onClick={() => window.location.reload()} style={{ padding: '10px 16px' }}>Reload WebUI</button>
        </div>
        {this.state.error?.stack && <pre style={{ marginTop: '20px', whiteSpace: 'pre-wrap', color: '#52657c', fontSize: '11px' }}>{this.state.error.stack}</pre>}
      </main>
    )
  }
}

createRoot(document.getElementById('root')).render(
  <StrictMode>
    <BrowserErrorBoundary>
      <App />
    </BrowserErrorBoundary>
  </StrictMode>,
)
