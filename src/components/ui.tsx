import { useEffect, useRef, useState, type ReactNode } from "react";

const reduced = () =>
  typeof window !== "undefined" &&
  window.matchMedia("(prefers-reduced-motion: reduce)").matches;

export function Reveal({
  children,
  className = "",
  delay = 0,
}: {
  children: ReactNode;
  className?: string;
  delay?: number;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const [on, setOn] = useState(false);

  useEffect(() => {
    if (reduced()) {
      setOn(true);
      return;
    }
    const el = ref.current;
    if (!el) return;
    const io = new IntersectionObserver(
      (entries) => {
        for (const e of entries) {
          if (e.isIntersecting) {
            setOn(true);
            io.disconnect();
          }
        }
      },
      { threshold: 0.1, rootMargin: "0px 0px -6% 0px" },
    );
    io.observe(el);
    return () => io.disconnect();
  }, []);

  return (
    <div
      ref={ref}
      className={className}
      style={{
        opacity: on ? 1 : 0,
        transform: on ? "none" : "translateY(18px)",
        transition: `opacity .7s ease ${delay}ms, transform .7s cubic-bezier(.2,.75,.3,1) ${delay}ms`,
      }}
    >
      {children}
    </div>
  );
}

export function SectionHead({
  num,
  kicker,
  title,
  intro,
  dark = false,
}: {
  num: string;
  kicker: string;
  title: ReactNode;
  intro?: ReactNode;
  dark?: boolean;
}) {
  return (
    <Reveal>
      <div className={`label flex items-center gap-4 ${dark ? "text-prussianlt" : "text-fiber"}`}>
        <span className={dark ? "text-[#e97a63]" : "text-vermilion"}>{num}</span>
        <span className={`h-px w-12 ${dark ? "bg-paper/40" : "bg-ink/30"}`} />
        <span>{kicker}</span>
      </div>
      <h2
        className={`mt-5 max-w-[19ch] font-display text-[clamp(1.9rem,4vw,3.2rem)] leading-[1.03] font-bold tracking-[-0.015em] ${
          dark ? "text-paper" : "text-ink"
        }`}
      >
        {title}
      </h2>
      {intro ? (
        <p
          className={`mt-4 max-w-[56ch] text-[15.5px] leading-[1.7] ${
            dark ? "text-paper/75" : "text-ink/75"
          }`}
        >
          {intro}
        </p>
      ) : null}
    </Reveal>
  );
}

export function Leader({
  k,
  v,
  strong = false,
}: {
  k: string;
  v: string;
  strong?: boolean;
}) {
  return (
    <div className={`flex items-baseline gap-2 ${strong ? "font-semibold" : ""}`}>
      <span className="shrink-0 text-[10.5px] font-semibold tracking-[0.14em] uppercase opacity-70">
        {k}
      </span>
      <span className="min-w-3 flex-1 -translate-y-1 border-b border-dotted border-current opacity-40" />
      <span className="max-w-[64%] shrink-0 text-right font-mono text-[12.5px] tabular-nums">
        {v}
      </span>
    </div>
  );
}
