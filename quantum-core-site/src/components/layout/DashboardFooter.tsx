import { Link } from 'react-router-dom';

export default function DashboardFooter() {
  const currentYear = new Date().getFullYear();

  return (
    <footer className="border-t border-white/[0.06] bg-black/40 backdrop-blur-xl">
      <div className="max-w-7xl mx-auto px-6 py-8">
        <div className="flex flex-col md:flex-row items-center justify-between gap-4">
          {/* Logo & Copyright */}
          <div className="flex items-center gap-4">
            <Link to="/" className="flex items-center gap-1 group">
              <span className="text-xl font-bold tracking-tighter text-white">
                NEX
                <span className="text-cyber-cyan group-hover:drop-shadow-[0_0_8px_#00FFFF] transition-all duration-300">
                  U
                </span>
                S
              </span>
            </Link>
            <span className="text-white/40 text-sm">
              © {currentYear} QuantumBridge. All rights reserved.
            </span>
          </div>

          {/* Links */}
          <div className="flex items-center gap-6">
            <a
              href="https://docs.quantumbridge.io"
              target="_blank"
              rel="noopener noreferrer"
              className="text-white/40 hover:text-cyber-cyan text-sm transition-colors"
            >
              Documentation
            </a>
            <a
              href="https://status.quantumbridge.io"
              target="_blank"
              rel="noopener noreferrer"
              className="text-white/40 hover:text-cyber-cyan text-sm transition-colors"
            >
              Status
            </a>
            <a
              href="https://github.com/quantumbridge"
              target="_blank"
              rel="noopener noreferrer"
              className="text-white/40 hover:text-cyber-cyan text-sm transition-colors"
            >
              GitHub
            </a>
            <a
              href="mailto:support@quantumbridge.io"
              className="text-white/40 hover:text-cyber-cyan text-sm transition-colors"
            >
              Support
            </a>
          </div>
        </div>
      </div>
    </footer>
  );
}
