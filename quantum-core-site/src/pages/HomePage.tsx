import Navbar from "../components/Navbar";
import Footer from "../components/Footer";
import GlobalAtmosphere from "../components/landing/GlobalAtmosphere";
import SeamlessVideoLoop from "../components/landing/SeamlessVideoLoop";
import LandingHero from "../components/landing/LandingHero";
import QuantumDefenseConsole from "../components/landing/QuantumDefenseConsole";
import RotaryTimeline from "../components/landing/RotaryTimeline";
import QuantumPricing from "../components/landing/QuantumPricing";

/**
 * New landing page with Lovable components.
 * One continuous immersive quantum system with connected sections.
 */
export default function HomePage() {
  return (
    <div className="min-h-screen relative text-white bg-black">
      {/* Seamless video background loop - deepest layer */}
      <div className="fixed inset-0" style={{ zIndex: -2 }}>
        <SeamlessVideoLoop
          src="/videos/178908-860734672.mp4"
          style={{ opacity: 0.4 }}
        />
      </div>

      {/* Global quantum atmosphere - layered above video */}
      <div className="fixed inset-0" style={{ zIndex: -1 }}>
        <GlobalAtmosphere />
      </div>

      {/* Navbar - fixed at top */}
      <Navbar />

      {/* Main content - all sections flow continuously */}
      <main className="relative z-10">
        {/* Hero Section */}
        <LandingHero />

        {/* Security Features Section */}
        <section id="security" className="relative">
          <QuantumDefenseConsole />
        </section>

        {/* How It Works Section */}
        <section id="how-it-works" className="relative">
          <RotaryTimeline />
        </section>

        {/* Pricing Section */}
        <section id="pricing" className="relative">
          <QuantumPricing />
        </section>

        {/* Footer */}
        <Footer />
      </main>
    </div>
  );
}
