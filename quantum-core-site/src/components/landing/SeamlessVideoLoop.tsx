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
 * Playback only starts once the active clip can play through without
 * stalling (canplaythrough), which is what keeps it smooth from the first
 * frame instead of sticking/buffering on open. The idle clip is pre-seeked
 * to t=0 and pre-buffered while the active one plays, so the crossfade swap
 * is instant.
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
  const activeRef = useRef<"A" | "B">("A");
  const switchingRef = useRef(false);
  const startedRef = useRef(false);

  // Keep the latest active buffer readable inside the stable timeupdate
  // listener without re-subscribing on every A↔B swap.
  useEffect(() => {
    activeRef.current = active;
  }, [active]);

  useEffect(() => {
    const a = videoARef.current;
    const b = videoBRef.current;
    if (!a || !b) return;

    // Start A only once it has buffered enough to play through without
    // stalling. autoPlay is intentionally NOT set — playing too early is
    // what made the hero stick and buffer on first load.
    const startA = () => {
      if (startedRef.current) return;
      startedRef.current = true;
      a.play().catch((error) => console.error("Video A failed to play:", error));
    };
    if (a.readyState >= HTMLMediaElement.HAVE_ENOUGH_DATA) startA();
    else a.addEventListener("canplaythrough", startA, { once: true });

    // Pre-warm B: prime it at t=0 as soon as it has data, so the first
    // crossfade swap is instant instead of buffering at the seam.
    const primeB = () => {
      try {
        b.currentTime = 0;
      } catch {
        /* readyState too low to seek yet; primes on a later loadeddata */
      }
    };
    if (b.readyState >= HTMLMediaElement.HAVE_CURRENT_DATA) primeB();
    else b.addEventListener("loadeddata", primeB, { once: true });

    const onTimeUpdate = (e: Event) => {
      const current = e.currentTarget as HTMLVideoElement;
      const act = activeRef.current;
      const isActive =
        (act === "A" && current === a) || (act === "B" && current === b);
      if (!isActive || switchingRef.current) return;

      const duration = current.duration;
      if (!duration || !isFinite(duration)) return;

      const remaining = duration - current.currentTime;
      if (remaining <= crossfade) {
        switchingRef.current = true;
        const next = current === a ? b : a;
        const nextLabel = current === a ? "B" : "A";
        try {
          next.currentTime = 0;
        } catch {
          /* ignore — will seek again on next pass */
        }
        // Flip opacity immediately so the crossfade starts on time; play()
        // runs in parallel. Awaiting play() before swapping caused late
        // swaps and a visible hitch at the loop point.
        setActive(nextLabel);
        next
          .play()
          .catch((error) => console.error("Video crossfade failed:", error))
          .finally(() => {
            window.setTimeout(() => {
              switchingRef.current = false;
            }, crossfade * 1000 + 50);
          });
      }
    };

    a.addEventListener("timeupdate", onTimeUpdate);
    b.addEventListener("timeupdate", onTimeUpdate);
    return () => {
      a.removeEventListener("timeupdate", onTimeUpdate);
      b.removeEventListener("timeupdate", onTimeUpdate);
      a.removeEventListener("canplaythrough", startA);
      b.removeEventListener("loadeddata", primeB);
    };
  }, [crossfade]); // listeners added once; latest active buffer read via activeRef

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
