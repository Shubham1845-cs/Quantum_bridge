import { motion } from "framer-motion";
import { useNavigate } from "react-router-dom";
import type { Product } from "../data/products";

interface Props {
  product: Product;
}

const ease = [0.22, 1, 0.36, 1] as const;

const revealVariant = {
  hidden: { opacity: 0, y: 60 },
  visible: { opacity: 1, y: 0, transition: { duration: 0.8, ease } },
};

export default function CommerceSection({ product }: Props) {
  const navigate = useNavigate();

  return (
    <section className="relative py-32 px-6" id="network">
      {/* Background glow */}
      <div
        className="absolute bottom-0 right-0 w-[600px] h-[600px] rounded-full blur-[180px] opacity-[0.05] pointer-events-none"
        style={{ background: product.gradient }}
      />

      <div className="relative max-w-4xl mx-auto">
        <motion.div
          initial="hidden"
          whileInView="visible"
          viewport={{ once: true, margin: "-100px" }}
          variants={revealVariant}
          className="rounded-3xl border overflow-hidden backdrop-blur-sm"
          style={{
            borderColor: `${product.themeColor}12`,
            background: "rgba(255,255,255,0.02)",
          }}
        >
          {/* Header bar with gradient */}
          <div
            className="px-8 py-6 flex items-center justify-between"
            style={{ background: product.gradient }}
          >
            <div>
              <h4
                className="text-black font-bold text-2xl tracking-tight"
                id="commerce-product-name"
              >
                {product.name}
              </h4>
              <p className="text-black/60 text-sm font-medium">
                {product.subName}
              </p>
            </div>
            <div className="text-right">
              <div
                className="text-black font-bold text-4xl tracking-tight"
                id="commerce-price"
              >
                {product.buyNowSection.price}
              </div>
              <div className="text-black/50 text-xs font-medium">
                {product.buyNowSection.unit}
              </div>
            </div>
          </div>

          <div className="p-8">
            {/* Spec badges */}
            <div className="flex flex-wrap gap-3 mb-10">
              {product.buyNowSection.specs.map((spec) => (
                <span
                  key={spec}
                  className="px-4 py-1.5 text-[10px] font-bold rounded-full border tracking-wider uppercase"
                  style={{
                    borderColor: `${product.themeColor}25`,
                    color: product.themeColor,
                    background: `${product.themeColor}08`,
                  }}
                >
                  {spec}
                </span>
              ))}
            </div>

            {/* CTA buttons */}
            <div className="flex gap-4 mb-10">
              <motion.button
                whileHover={{
                  scale: 1.02,
                  boxShadow: `0 0 30px ${product.themeColor}25, 0 0 60px ${product.themeColor}10`,
                }}
                whileTap={{ scale: 0.98 }}
                onClick={() => navigate("/register")}
                className="flex-1 py-4 rounded-2xl font-bold text-black text-base relative overflow-hidden tracking-wide"
                style={{ background: product.gradient }}
                id="deploy-quantum-core"
              >
                Deploy Quantum Core
              </motion.button>

              <motion.button
                whileHover={{ scale: 1.02 }}
                whileTap={{ scale: 0.98 }}
                onClick={() => navigate("/login")}
                className="px-8 py-4 rounded-2xl font-bold text-xs border transition-colors tracking-wider uppercase"
                style={{
                  borderColor: `${product.themeColor}25`,
                  color: product.themeColor,
                  background: `${product.themeColor}05`,
                }}
                id="request-demo-btn"
              >
                Sign In
              </motion.button>
            </div>

            {/* Info cards */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div
                className="flex gap-4 p-5 rounded-2xl border"
                style={{
                  background: `${product.themeColor}03`,
                  borderColor: `${product.themeColor}08`,
                }}
              >
                <div className="text-2xl">⚡</div>
                <div>
                  <div className="text-white text-sm font-bold mb-1">
                    Secure Transport
                  </div>
                  <div className="text-white/35 text-xs leading-relaxed font-light">
                    {product.buyNowSection.deliveryPromise}
                  </div>
                </div>
              </div>
              <div
                className="flex gap-4 p-5 rounded-2xl border"
                style={{
                  background: `${product.themeColor}03`,
                  borderColor: `${product.themeColor}08`,
                }}
              >
                <div className="text-2xl">🛡️</div>
                <div>
                  <div className="text-white text-sm font-bold mb-1">
                    Warranty
                  </div>
                  <div className="text-white/35 text-xs leading-relaxed font-light">
                    {product.buyNowSection.warranty}
                  </div>
                </div>
              </div>
            </div>
          </div>
        </motion.div>
      </div>
    </section>
  );
}
