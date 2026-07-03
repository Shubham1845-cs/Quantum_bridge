import { useEffect, useRef, useState, type CSSProperties } from "react";

type Props = {
  src: string;
  className?: string;
  style?: CSSProperties;
  /** Crossfade duration in seconds */
  crossfade?: number;
};

/**
 * Seamless infinite video loop using dual-buffer crossfade.
 * Two stacked <video> elements alternate playback; near the end of the
 * active clip, the idle clip is started and faded in while the active
 * one fades out — producing an invisible loop point.
 * 
 * Video URL: https://res.cloudinary.com/dashtm8a6/video/upload/v1779628707/mp__qqmqfc.mp4
 */
export default function SeamlessVideoLoop({
  src,
  className,
  style,
  crossfade = 1.2,
}: Props) {
  const videoARef = useRef<HTMLVideoElement>(null);
  const videoBRef = useRef<HTMLVideoElement>(null);
  const [active, setActive] = useState<"A" | "B">("A");
  const switchingRef = useRef(false);

  useEffect(() => {
    const a = videoARef.current;
    const b = videoBRef.current;
    if (!a || !b) return;

    // Start playing video A with error handling
    a.play().catch((error) => {
      console.error('Video A failed to play:', error);
      // Fallback: component will still render with static background
    });

    const onTimeUpdate = (e: Event) => {
      const current = e.currentTarget as HTMLVideoElement;
      const isActive =
        (active === "A" && current === a) || (active === "B" && current === b);
      if (!isActive || switchingRef.current) return;

      const duration = current.duration;
      if (!duration || !isFinite(duration)) return;

      const remaining = duration - current.currentTime;
      if (remaining <= crossfade) {
        switchingRef.current = true;
        const next = current === a ? b : a;
        next.currentTime = 0;
        next.play()
          .then(() => {
            setActive(current === a ? "B" : "A");
            // release lock slightly after fade completes
            window.setTimeout(() => {
              switchingRef.current = false;
            }, crossfade * 1000 + 50);
          })
          .catch((error) => {
            console.error('Video crossfade failed:', error);
            switchingRef.current = false;
          });
      }
    };

    a.addEventListener("timeupdate", onTimeUpdate);
    b.addEventListener("timeupdate", onTimeUpdate);
    return () => {
      a.removeEventListener("timeupdate", onTimeUpdate);
      b.removeEventListener("timeupdate", onTimeUpdate);
    };
  }, [active, crossfade]);

  const baseStyle: CSSProperties = {
    transition: `opacity ${crossfade}s ease-in-out`,
    willChange: "opacity",
    backfaceVisibility: "hidden",
    transform: "translateZ(0)",
  };

  return (
    <div
      className={className}
      style={{ position: "absolute", inset: 0, ...style }}
      aria-hidden
    >
      <video
        ref={videoARef}
        autoPlay
        muted
        playsInline
        preload="auto"
        className="absolute inset-0 w-full h-full object-cover"
        style={{ ...baseStyle, opacity: active === "A" ? 1 : 0 }}
      >
        <source src={src} type="video/mp4" />
      </video>
      <video
        ref={videoBRef}
        muted
        playsInline
        preload="auto"
        className="absolute inset-0 w-full h-full object-cover"
        style={{ ...baseStyle, opacity: active === "B" ? 1 : 0 }}
      >
        <source src={src} type="video/mp4" />
      </video>
      {/* Subtle blur blending overlay to smooth any residual flicker */}
      <div
        className="absolute inset-0 pointer-events-none"
        style={{
          backdropFilter: "blur(0.5px)",
          background:
            "radial-gradient(ellipse at center, transparent 60%, rgba(0,0,0,0.08) 100%)",
        }}
      />
    </div>
  );
}
