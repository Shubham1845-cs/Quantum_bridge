export default function Footer() {
  return (
    <footer className="bg-black border-t border-white/5 pt-20 pb-10 px-6" id="footer">
      <div className="max-w-7xl mx-auto">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-12 mb-16">
          {/* Brand */}
          <div className="md:col-span-1">
            <div className="flex items-center gap-1 mb-5">
              <span className="text-2xl font-bold tracking-tighter text-white">
                Quantum
                <span className="text-cyber-cyan">Bridge</span>
              </span>
              <span className="w-1.5 h-1.5 rounded-full bg-cyber-cyan ml-0.5 -mt-3" />
            </div>
            <p className="text-white/25 text-sm leading-relaxed font-light">
              Quantum-safe API proxy infrastructure. Legacy APIs, post-quantum
              protected.
            </p>
            <div className="flex gap-3 mt-6">
              {[
                { label: "X", icon: "𝕏" },
                { label: "GitHub", icon: "GH" },
                { label: "LinkedIn", icon: "in" },
              ].map((s) => (
                <a
                  key={s.label}
                  href="#"
                  className="w-9 h-9 rounded-lg bg-white/[0.03] hover:bg-cyber-cyan/10 border border-white/5 hover:border-cyber-cyan/25 flex items-center justify-center text-white/25 hover:text-cyber-cyan transition-all duration-300 text-xs font-bold"
                  aria-label={s.label}
                  id={`footer-social-${s.label.toLowerCase()}`}
                >
                  {s.icon}
                </a>
              ))}
            </div>
          </div>

          {/* Documentation */}
          <div>
            <h5 className="text-white font-bold text-[10px] tracking-[0.3em] uppercase mb-6">
              Documentation
            </h5>
            <ul className="space-y-3">
              {[
                "Getting Started",
                "Installation Guide",
                "Configuration",
                "Migration",
                "Changelog",
              ].map((item) => (
                <li key={item}>
                  <a
                    href="#"
                    className="text-white/25 hover:text-cyber-cyan text-sm transition-colors duration-300 font-light"
                  >
                    {item}
                  </a>
                </li>
              ))}
            </ul>
          </div>

          {/* API Access */}
          <div>
            <h5 className="text-white font-bold text-[10px] tracking-[0.3em] uppercase mb-6">
              API Access
            </h5>
            <ul className="space-y-3">
              {[
                "REST API",
                "GraphQL",
                "WebSocket",
                "SDK Downloads",
                "Rate Limits",
              ].map((item) => (
                <li key={item}>
                  <a
                    href="#"
                    className="text-white/25 hover:text-cyber-cyan text-sm transition-colors duration-300 font-light"
                  >
                    {item}
                  </a>
                </li>
              ))}
            </ul>
          </div>

          {/* System Status */}
          <div>
            <h5 className="text-white font-bold text-[10px] tracking-[0.3em] uppercase mb-6">
              System Status
            </h5>
            <div className="space-y-4">
              {[
                { name: "Core Network", status: "Operational" },
                { name: "API Gateway", status: "Operational" },
                { name: "Edge Nodes", status: "Operational" },
              ].map((service) => (
                <div
                  key={service.name}
                  className="flex items-center justify-between"
                >
                  <span className="text-white/25 text-sm font-light">
                    {service.name}
                  </span>
                  <div className="flex items-center gap-2">
                    <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
                    <span className="text-emerald-400 text-[10px] font-medium tracking-wider">
                      {service.status}
                    </span>
                  </div>
                </div>
              ))}
            </div>
            <div
              className="mt-6 p-4 rounded-xl border border-white/5 bg-white/[0.02]"
              id="uptime-card"
            >
              <div className="text-white/40 text-[10px] font-medium tracking-wider uppercase">
                Uptime
              </div>
              <div className="text-cyber-cyan text-2xl font-bold tracking-tight mt-1">
                99.999%
              </div>
              <div className="text-white/15 text-[10px] mt-1 font-light">
                Last 365 days
              </div>
            </div>
          </div>
        </div>

        {/* Bottom bar */}
        <div className="border-t border-white/5 pt-8 flex flex-col md:flex-row items-center justify-between gap-4">
          <p className="text-white/15 text-xs font-light">
            © 2026 QuantumBridge. All rights reserved. Post-quantum secured
            infrastructure.
          </p>
          <div className="flex gap-6">
            {["Privacy", "Terms", "Security", "Compliance"].map((item) => (
              <a
                key={item}
                href="#"
                className="text-white/15 hover:text-white/35 text-xs transition-colors duration-300 font-light"
              >
                {item}
              </a>
            ))}
          </div>
        </div>
      </div>
    </footer>
  );
}
