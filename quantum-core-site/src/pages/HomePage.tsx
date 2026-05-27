import { products } from "../data/products";
import Navbar from "../components/Navbar";
import HeroSection from "../components/HeroSection";
import DetailsSection from "../components/DetailsSection";
import CommerceSection from "../components/CommerceSection";
import Footer from "../components/Footer";

/**
 * The original marketing / landing page.
 * Extracted so App.tsx can focus on routing.
 */
export default function HomePage() {
  const product = products[0];

  return (
    <div className="min-h-screen relative text-white bg-black">
      <Navbar />

      {/* Background Video fixed behind all content */}
      <video
        autoPlay
        loop
        muted
        playsInline
        className="fixed inset-0 w-full h-full object-cover z-0 opacity-40 pointer-events-none"
      >
        <source src="/videos/178908-860734672.mp4" type="video/mp4" />
      </video>

      <main className="relative z-10">
        {/* Ambient background glow */}
        <div
          className="fixed inset-0 pointer-events-none z-0 transition-all duration-1000 mix-blend-screen"
          style={{
            background: `radial-gradient(ellipse 80% 60% at 50% 0%, ${product.themeColor}15 0%, transparent 70%)`,
          }}
        />

        <HeroSection product={product} />

        {/* Gradient Divider */}
        <div
          className="h-px w-full"
          style={{
            background: `linear-gradient(90deg, transparent, ${product.themeColor}30, transparent)`,
          }}
        />

        {/* Details & Tech Specs */}
        <div className="relative z-10 bg-black/40 backdrop-blur-md">
          <DetailsSection product={product} />
        </div>

        {/* Gradient Divider */}
        <div
          className="h-px w-full"
          style={{
            background: `linear-gradient(90deg, transparent, ${product.themeColor}20, transparent)`,
          }}
        />

        {/* Commerce / Buy Now */}
        <div className="relative z-10 bg-black/40 backdrop-blur-md">
          <CommerceSection product={product} />
        </div>

        <Footer />
      </main>
    </div>
  );
}
