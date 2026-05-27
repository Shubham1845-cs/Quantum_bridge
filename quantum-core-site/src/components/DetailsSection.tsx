import { motion } from "framer-motion";
import type { Product } from "../data/products";

interface Props {
  product: Product;
}

const ease = [0.22, 1, 0.36, 1] as const;

const revealVariant = {
  hidden: { opacity: 0, y: 60 },
  visible: { opacity: 1, y: 0, transition: { duration: 0.8, ease } },
};

export default function DetailsSection({ product }: Props) {
  return (
    <section
      className="relative py-32 px-6 overflow-hidden"
      id="technology"
    >
      {/* Background glow */}
      <div
        className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[800px] h-[600px] rounded-full blur-[150px] opacity-[0.06] pointer-events-none"
        style={{ background: product.gradient }}
      />

      <div className="relative max-w-6xl mx-auto">
        {/* — Architecture Section — */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-16 md:gap-24 items-center mb-32">
          <motion.div
            initial="hidden"
            whileInView="visible"
            viewport={{ once: true, margin: "-100px" }}
            variants={revealVariant}
          >
            <span
              className="text-[10px] font-bold tracking-[0.4em] uppercase mb-5 block"
              style={{ color: product.themeColor }}
            >
              Architecture
            </span>
            <h3
              className="text-4xl md:text-5xl lg:text-6xl font-bold text-white mb-8 leading-tight tracking-tight"
              id="details-title"
            >
              {product.detailsSection.title}
            </h3>
            <p className="text-white/40 text-lg leading-relaxed font-light">
              {product.detailsSection.description}
            </p>
            <div className="mt-10 flex flex-wrap gap-3">
              {product.features.map((f) => (
                <span
                  key={f}
                  className="px-5 py-2 rounded-full text-xs font-semibold border backdrop-blur-sm tracking-wider uppercase"
                  style={{
                    borderColor: `${product.themeColor}25`,
                    color: product.themeColor,
                    background: `${product.themeColor}08`,
                  }}
                >
                  {f}
                </span>
              ))}
            </div>
          </motion.div>

          <motion.div
            initial="hidden"
            whileInView="visible"
            viewport={{ once: true, margin: "-100px" }}
            variants={{
              hidden: { opacity: 0, y: 60 },
              visible: {
                opacity: 1,
                y: 0,
                transition: { delay: 0.2, duration: 0.8, ease },
              },
            }}
            className="relative"
          >
            <div
              className="rounded-3xl p-8 border backdrop-blur-sm"
              style={{
                background: `${product.themeColor}04`,
                borderColor: `${product.themeColor}12`,
              }}
            >
              {/* Stats grid */}
              <div className="grid grid-cols-3 gap-4 mb-8">
                {product.stats.map((stat) => (
                  <div
                    key={stat.label}
                    className="text-center p-5 rounded-2xl border"
                    style={{
                      background: `${product.themeColor}05`,
                      borderColor: `${product.themeColor}10`,
                    }}
                  >
                    <div
                      className="text-2xl md:text-3xl font-bold"
                      style={{ color: product.themeColor }}
                    >
                      {stat.val}
                    </div>
                    <div className="text-white/35 text-[10px] uppercase tracking-[0.2em] mt-2 font-medium">
                      {stat.label}
                    </div>
                  </div>
                ))}
              </div>

              {/* Spec check-marks */}
              <div className="space-y-4">
                {product.description.split(" - ").map((line, i) => (
                  <div key={i} className="flex items-center gap-4">
                    <div
                      className="w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0"
                      style={{ background: product.gradient }}
                    >
                      <svg
                        className="w-4 h-4 text-black"
                        fill="none"
                        viewBox="0 0 24 24"
                        stroke="currentColor"
                      >
                        <path
                          strokeLinecap="round"
                          strokeLinejoin="round"
                          strokeWidth={2.5}
                          d="M5 13l4 4L19 7"
                        />
                      </svg>
                    </div>
                    <span className="text-white/50 text-sm font-medium">
                      {line}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          </motion.div>
        </div>

        {/* — Ethereal Shielding / Tech Section — */}
        <motion.div
          initial="hidden"
          whileInView="visible"
          viewport={{ once: true, margin: "-100px" }}
          variants={revealVariant}
          className="text-center max-w-3xl mx-auto"
          id="specifications"
        >
          <span
            className="text-[10px] font-bold tracking-[0.4em] uppercase mb-5 block"
            style={{ color: product.themeColor }}
          >
            Defense Systems
          </span>
          <h3
            className="text-4xl md:text-5xl lg:text-6xl font-bold text-white mb-8 tracking-tight"
            id="tech-title"
          >
            {product.techSection.title}
          </h3>
          <p className="text-white/40 text-lg leading-relaxed font-light">
            {product.techSection.description}
          </p>
          <div className="mt-12 flex justify-center flex-wrap gap-4">
            {product.buyNowSection.specs.map((spec) => (
              <div
                key={spec}
                className="flex items-center gap-3 px-6 py-3 rounded-full text-xs font-bold border tracking-wider uppercase"
                style={{
                  borderColor: `${product.themeColor}20`,
                  color: product.themeColor,
                  background: `${product.themeColor}05`,
                }}
              >
                <span
                  className="w-1.5 h-1.5 rounded-full"
                  style={{ background: product.themeColor }}
                />
                {spec}
              </div>
            ))}
          </div>
        </motion.div>
      </div>
    </section>
  );
}
