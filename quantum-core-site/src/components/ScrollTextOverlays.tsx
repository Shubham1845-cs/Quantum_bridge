import { motion, useTransform } from "framer-motion";
import type { MotionValue } from "framer-motion";
import type { Product } from "../data/products";

interface Props {
  product: Product;
  scrollProgress: MotionValue<number>;
}

export default function ScrollTextOverlays({ product, scrollProgress }: Props) {
  // Section 1: "The Void." — fades in at scroll start, out before Section 2
  const s1Opacity = useTransform(
    scrollProgress,
    [0, 0.06, 0.18, 0.24],
    [0, 1, 1, 0]
  );
  const s1Y = useTransform(scrollProgress, [0, 0.06], [60, 0]);

  // Section 2: "Igniting the Stream."
  const s2Opacity = useTransform(
    scrollProgress,
    [0.25, 0.31, 0.43, 0.49],
    [0, 1, 1, 0]
  );
  const s2Y = useTransform(scrollProgress, [0.25, 0.31], [60, 0]);

  // Section 3: "Hyper-Speed Transmission."
  const s3Opacity = useTransform(
    scrollProgress,
    [0.50, 0.56, 0.68, 0.74],
    [0, 1, 1, 0]
  );
  const s3Y = useTransform(scrollProgress, [0.50, 0.56], [60, 0]);

  // Section 4: "Welcome to the Future of Networking."
  const s4Opacity = useTransform(
    scrollProgress,
    [0.75, 0.81, 0.92, 0.98],
    [0, 1, 1, 0]
  );
  const s4Y = useTransform(scrollProgress, [0.75, 0.81], [60, 0]);

  const sections = [
    {
      data: product.section1,
      opacity: s1Opacity,
      y: s1Y,
      align: "left" as const,
    },
    {
      data: product.section2,
      opacity: s2Opacity,
      y: s2Y,
      align: "right" as const,
    },
    {
      data: product.section3,
      opacity: s3Opacity,
      y: s3Y,
      align: "left" as const,
    },
    {
      data: product.section4,
      opacity: s4Opacity,
      y: s4Y,
      align: "center" as const,
    },
  ];

  return (
    <>
      {sections.map((sec, i) => (
        <motion.div
          key={i}
          style={{ opacity: sec.opacity, y: sec.y }}
          className={`absolute pointer-events-none ${
            sec.align === "left"
              ? "bottom-24 left-8 md:left-16 text-left max-w-xl"
              : sec.align === "right"
              ? "bottom-24 right-8 md:right-16 text-right max-w-xl"
              : "bottom-24 left-1/2 -translate-x-1/2 text-center max-w-3xl w-full px-6"
          }`}
        >
          {/* Title with gradient */}
          <h2
            className="text-4xl md:text-6xl lg:text-7xl font-bold leading-[1.05] tracking-tight"
            style={{
              textShadow: `0 0 60px ${product.themeColor}40, 0 0 120px ${product.themeColor}15`,
            }}
          >
            <span className="text-gradient-cyan">{sec.data.title}</span>
          </h2>

          {/* Subtitle */}
          {sec.data.subtitle && (
            <p className="mt-4 text-base md:text-xl text-white/50 font-light leading-relaxed tracking-wide">
              {sec.data.subtitle}
            </p>
          )}

          {/* Decorative accent line */}
          <div
            className="mt-5 h-px w-20 opacity-40"
            style={{
              background: product.gradient,
              marginLeft:
                sec.align === "right"
                  ? "auto"
                  : sec.align === "center"
                  ? "auto"
                  : "0",
              marginRight: sec.align === "center" ? "auto" : "0",
            }}
          />
        </motion.div>
      ))}
    </>
  );
}
