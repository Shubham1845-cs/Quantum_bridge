import { useState, type FormEvent } from 'react';
import toast from 'react-hot-toast';
import {
  Mail,
  MapPin,
  Phone,
  Shield,
  Activity,
  Code,
  Eye,
  ExternalLink,
} from 'lucide-react';
import { Link } from 'react-router-dom';

const data = {
  features: {
    bridge: '#vault',
    defense: '#defense-console',
    api: '#install',
    monitoring: '#vault',
  },
  about: {
    company: '/about',
    team: '/team',
    careers: '/careers',
    blog: '/blog',
  },
  help: {
    docs: '/docs',
    support: '/support',
    faqs: '/faqs',
  },
  contact: {
    email: 'gaikwadshubham62173@gmail.com',
    phone: '+91 7499766945',
    address: 'Building Quantum-Safe Infrastructure',
  },
  company: {
    name: 'QuantumBridge',
    description:
      'Post-quantum cryptography proxy for legacy systems. Protect your APIs from harvest-now-decrypt-later attacks with dual-signature verification.',
  },
};

const featureLinks = [
  { text: 'Quantum Bridge', href: data.features.bridge, icon: Shield },
  { text: 'Defense Console', href: data.features.defense, icon: Activity },
  { text: 'API Integration', href: data.features.api, icon: Code },
  { text: 'Real-time Monitoring', href: data.features.monitoring, icon: Eye },
];

const aboutLinks = [
  { text: 'About Us', href: data.about.company },
  { text: 'Our Team', href: data.about.team },
  { text: 'Careers', href: data.about.careers },
  { text: 'Blog', href: data.about.blog },
];

const helpfulLinks = [
  { text: 'Documentation', href: data.help.docs },
  { text: 'Support', href: data.help.support },
  { text: 'FAQs', href: data.help.faqs },
];

const contactInfo = [
  { icon: Mail, text: data.contact.email, href: `mailto:${data.contact.email}` },
  { icon: Phone, text: data.contact.phone, href: `tel:${data.contact.phone}` },
  { icon: MapPin, text: data.contact.address, isAddress: true },
];

const Logo = () => (
  <svg
    xmlns="http://www.w3.org/2000/svg"
    width="32"
    height="32"
    fill="none"
    overflow="visible"
    viewBox="0 0 256 256"
  >
    <path
      d="M 64 128 L 64.5 128 L 32 95 L 0 64 L 0 0 L 64 0 L 128 64 L 128 64.5 L 161 32 L 192 0 L 256 0 L 256 64 L 192 128 L 128 128 L 128 192 L 96 223 L 63.5 256 L 0 256 L 0 192 Z M 256 192 L 224 223 L 191.5 256 L 128 256 L 128 192 L 192 128 L 256 128 Z"
      fill="#FFFFFF"
    />
  </svg>
);

export default function Footer() {
  const [email, setEmail] = useState('');

  // ponytail: no backend newsletter endpoint exists — client-side acknowledgement only.
  // Add a POST /newsletter/subscribe endpoint + persistence when real subscriptions are needed.
  const handleSubscribe = (e: FormEvent) => {
    e.preventDefault();
    const value = email.trim();
    if (!value) {
      toast.error('Please enter your email');
      return;
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) {
      toast.error('Please enter a valid email address');
      return;
    }
    toast.success('Subscribed! Watch your inbox for quantum-safe updates.');
    setEmail('');
  };

  return (
    <footer className="relative bg-gradient-to-b from-[rgba(10,5,20,0.95)] to-black backdrop-blur-sm overflow-hidden -mt-16">
      {/* Background effects */}
      <div className="absolute inset-0 pointer-events-none">
        <div className="absolute bottom-0 left-1/2 -translate-x-1/2 w-[900px] h-[400px] rounded-full opacity-[0.03] blur-[150px] bg-gradient-to-br from-cyber-cyan to-neon-purple" />
      </div>

      <div className="relative z-10 mx-auto max-w-7xl px-6 pt-16 pb-6 sm:px-8 lg:px-8 lg:pt-24">
        {/* Smooth gradient blend from Help section */}
        <div 
          className="absolute top-0 left-0 right-0 h-32 pointer-events-none"
          style={{
            background: 'linear-gradient(180deg, transparent 0%, rgba(10,5,20,0.5) 50%, rgba(10,5,20,0.95) 100%)',
          }}
        />
        
        {/* Newsletter Section with Video */}
        <div className="mb-16 grid grid-cols-1 gap-8 lg:grid-cols-2 items-center">
          <div>
            <h2 className="text-3xl font-bold tracking-tight text-white mb-4">
              Stay ahead with <span style={{ color: '#67e8f9' }}>QuantumBridge</span>
            </h2>
            <p className="text-white/60 mb-6 max-w-md">
              Join thousands of professionals who trust QuantumBridge for quantum-safe API protection.
            </p>
            <form onSubmit={handleSubscribe} className="flex gap-3 max-w-md">
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="Enter your email"
                aria-label="Email address"
                className="flex-1 px-4 py-3 rounded-lg bg-white/[0.04] border border-white/[0.08] text-white text-sm placeholder-white/40 focus:outline-none focus:border-cyan-400/50 focus:ring-1 focus:ring-cyan-400/25 transition-all"
              />
              <button type="submit" className="px-6 py-3 rounded-lg font-semibold text-black bg-gradient-to-r from-cyan-400 to-purple-500 hover:from-cyan-300 hover:to-purple-400 transition-all">
                Subscribe
              </button>
            </form>
          </div>

          {/* Video Card */}
          <div className="relative rounded-2xl overflow-hidden border border-white/10 shadow-2xl h-64 lg:h-80">
            <video
              autoPlay
              loop
              muted
              playsInline
              className="w-full h-full object-cover"
            >
              <source src="https://res.cloudinary.com/dashtm8a6/video/upload/v1780173523/no_htxeus.mp4" type="video/mp4" />
            </video>
            <div className="absolute inset-0 bg-gradient-to-t from-black/60 via-transparent to-transparent" />
          </div>
        </div>

        {/* Main Footer Content */}
        <div className="grid grid-cols-1 gap-8 lg:grid-cols-3 border-t border-white/5 pt-12">
          {/* Company Info */}
          <div>
            <div className="flex items-center gap-2 mb-6">
              <Logo />
              <span className="text-2xl font-semibold text-white">{data.company.name}</span>
            </div>
            <p className="text-white/50 max-w-md leading-relaxed mb-8">
              {data.company.description}
            </p>
          </div>

          {/* Links Grid */}
          <div className="grid grid-cols-1 gap-8 sm:grid-cols-3 lg:col-span-2">
            {/* Features */}
            <div>
              <p className="text-lg font-semibold text-white mb-6">Features</p>
              <ul className="space-y-4 text-sm">
                {featureLinks.map(({ text, href, icon: Icon }) => (
                  <li key={text}>
                    <a
                      href={href}
                      className="text-white/60 hover:text-cyan-400 transition-colors flex items-center gap-2"
                    >
                      <Icon size={14} style={{ color: '#67e8f9' }} />
                      {text}
                    </a>
                  </li>
                ))}
              </ul>
            </div>

            {/* Company */}
            <div>
              <p className="text-lg font-semibold text-white mb-6">Company</p>
              <ul className="space-y-4 text-sm">
                {aboutLinks.map(({ text, href }) => (
                  <li key={text}>
                    <Link
                      to={href}
                      className="text-white/60 hover:text-cyan-400 transition-colors"
                    >
                      {text}
                    </Link>
                  </li>
                ))}
              </ul>
            </div>

            {/* Contact */}
            <div>
              <p className="text-lg font-semibold text-white mb-6">Contact Us</p>
              <ul className="space-y-4 text-sm">
                {contactInfo.map(({ icon: Icon, text, href, isAddress }) => (
                  <li key={text}>
                    {href ? (
                      <a
                        href={href}
                        className="flex items-start gap-2 text-white/60 hover:text-cyan-400 transition-colors"
                      >
                        <Icon className="w-4 h-4 mt-0.5 shrink-0" style={{ color: '#67e8f9' }} />
                        <span className="flex-1">{text}</span>
                      </a>
                    ) : (
                      <div className="flex items-start gap-2 text-white/60">
                        <Icon className="w-4 h-4 mt-0.5 shrink-0" style={{ color: '#67e8f9' }} />
                        {isAddress ? (
                          <address className="flex-1 not-italic">{text}</address>
                        ) : (
                          <span className="flex-1">{text}</span>
                        )}
                      </div>
                    )}
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </div>

        {/* Bottom Bar */}
        <div className="mt-12 border-t border-white/5 pt-6">
          <div className="flex flex-col sm:flex-row justify-between items-center gap-4 text-sm text-white/40">
            <p>&copy; {new Date().getFullYear()} {data.company.name}. All rights reserved.</p>
            <div className="flex gap-6">
              <Link to="/privacy" className="hover:text-white/70 transition-colors">
                Privacy Policy
              </Link>
              <Link to="/terms" className="hover:text-white/70 transition-colors">
                Terms of Service
              </Link>
            </div>
          </div>
        </div>
      </div>
    </footer>
  );
}
