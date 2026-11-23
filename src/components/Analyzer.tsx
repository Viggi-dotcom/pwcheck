import { useMemo, useState } from "react";
import {
  analyze,
  avalanche,
  formatDuration,
  makeSalt,
  randomPassphrase,
  randomPassword,
  sha256Hex,
  type Profile,
  type Verdict,
} from "../lib/analyzer";
import { Leader, Reveal, SectionHead } from "./ui";

const SEGMENTS = 48;

const VERDICT_COLOR: Record<Verdict, string> = {
  ACCEPT: "text-viridian",
  REVIEW: "text-[#9a6a10]",
  REJECT: "text-vermilion",
};

const SEV_COLOR: Record<string, string> = {
  critical: "text-vermilion",
  high: "text-[#8a5e0f]",
  medium: "text-prussian/80",
};

const GLYPH: Record<string, string> = { pass: "✓", fail: "✗", na: "–" };
const GLYPH_COLOR: Record<string, string> = {
  pass: "text-viridian",
  fail: "text-vermilion",
  na: "text-fiber/60",
};

function RuleRow({
  id,
  label,
  method,
  status,
  note,
  severity,
}: {
  id: string;
  label: string;
  method: string;
  status: "pass" | "fail" | "na";
  note: string;
  severity: string;
}) {
  return (
    <div className="grid grid-cols-[1.2rem_1fr] gap-x-3 px-5 py-3.5 sm:grid-cols-[1.2rem_1fr_auto]">
      <span
        className={`pt-[1px] font-mono text-[15px] leading-none ${GLYPH_COLOR[status]}`}
        aria-hidden
      >
        {GLYPH[status]}
      </span>
      <div className="min-w-0">
        <div className="flex flex-wrap items-baseline gap-x-2.5 gap-y-1">
          <span className="font-mono text-[11px] text-fiber tabular-nums">{id}</span>
          <span
            className={`text-[14.5px] font-medium ${
              status === "fail" ? "text-ink" : "text-ink/85"
            }`}
          >
            {label}
          </span>
          {status === "fail" && (
            <span className={`label ${SEV_COLOR[severity]}`}>{severity}</span>
          )}
        </div>
        <div className="mt-1 font-mono text-[11.5px] leading-[1.55] break-words text-fiber">
          {note}
        </div>
      </div>
      <span className="label hidden pt-1 text-right text-fiber sm:block">{method}</span>
    </div>
  );
}

export function Analyzer() {
  const [pw, setPw] = useState("Sunshine!24");
  const [profile, setProfile] = useState<Profile>("strict");
  const [reveal, setReveal] = useState(true);
  const [salt, setSalt] = useState(() => makeSalt());

  const empty = pw.length === 0;
  const a = useMemo(() => analyze(pw, profile), [pw, profile]);
  const digest = useMemo(() => (empty ? "" : sha256Hex(pw)), [pw, empty]);
  const salted = useMemo(() => (empty ? "" : sha256Hex(salt + pw)), [pw, salt, empty]);
  const av = useMemo(() => (empty ? null : avalanche(pw)), [pw, empty]);

  const fill =
    a.verdict === "ACCEPT"
      ? "bg-viridian"
      : a.verdict === "REVIEW"
        ? "bg-ochre"
        : "bg-vermilion";

  const floor = profile === "strict" ? 50 : 40;

  return (
    <section id="analyzer" className="border-b border-ink/20">
      <div className="mx-auto max-w-[1240px] px-5 py-16 sm:px-8 lg:py-24">
        <SectionHead
          num="02"
          kicker="Live inspection"
          title={
            <>
              Run any value through the <span className="italic font-medium">policy engine</span>
            </>
          }
          intro="The browser port of the Python core: same eight controls, same penalty model, same verdict. Type, generate, switch profiles — the carbon copy re-prints on every keystroke."
        />

        <div className="mt-10 grid gap-8 lg:grid-cols-[1.12fr_1fr] lg:gap-10">
          {/* ------------------------------ inspection sheet ------------------------------ */}
          <Reveal>
            <div className="border border-ink/30 bg-paper2/55 shadow-[6px_7px_0_rgba(26,28,26,0.07)]">
              <div className="flex flex-wrap items-center justify-between gap-3 border-b border-ink/30 px-5 py-3">
                <span className="label text-fiber">Form PS-1 · Inspection sheet</span>
                <div className="flex border border-ink/30 p-[3px]">
                  {(["baseline", "strict"] as Profile[]).map((p) => (
                    <button
                      key={p}
                      onClick={() => setProfile(p)}
                      aria-pressed={profile === p}
                      className={`label px-3 py-1.5 transition-colors ${
                        profile === p
                          ? "bg-prussian text-paper"
                          : "text-fiber hover:text-ink"
                      }`}
                    >
                      {p}
                    </button>
                  ))}
                </div>
              </div>

              <div className="label flex flex-wrap gap-x-5 gap-y-1 border-b border-ink/20 px-5 py-2 text-fiber">
                <span>min {profile === "strict" ? 12 : 8} chars</span>
                <span>{profile === "strict" ? "4 of 4" : "3 of 4"} pools</span>
                <span>floor {floor} bits</span>
                <span className="text-vermilion">
                  {profile === "strict" ? "auditor setting" : "enterprise setting"}
                </span>
              </div>

              {/* input + stamp */}
              <div className="px-5 pt-6 pb-5">
                <label htmlFor="pw" className="label text-fiber">
                  Password under test
                </label>
                <div className="mt-3 flex flex-col gap-5 sm:flex-row sm:items-start">
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-3">
                      <input
                        id="pw"
                        type={reveal ? "text" : "password"}
                        value={pw}
                        onChange={(e) => setPw(e.target.value)}
                        placeholder="type a value…"
                        spellCheck={false}
                        autoComplete="off"
                        autoCapitalize="off"
                        className="min-w-0 flex-1 border-b-2 border-ink/40 bg-transparent pb-2 font-mono text-[clamp(1.05rem,2.4vw,1.4rem)] tracking-[0.03em] text-ink outline-none transition-colors focus:border-vermilion"
                      />
                      <button
                        onClick={() => setReveal((r) => !r)}
                        className="label shrink-0 text-fiber transition-colors hover:text-ink"
                      >
                        {reveal ? "hide" : "show"}
                      </button>
                    </div>

                    <div className="mono-num mt-3 flex flex-wrap gap-x-5 gap-y-1 text-[11.5px] text-fiber">
                      <span>len {a.length}</span>
                      <span>pool {a.pool || "—"}</span>
                      <span>raw {a.raw.toFixed(1)} b</span>
                      <span>{a.isPassphrase ? `${a.tokens.length} tokens` : "single token"}</span>
                    </div>

                    <div className="mt-4 flex flex-wrap gap-2">
                      <button
                        onClick={() => setPw(randomPassword())}
                        className="label border border-ink/35 px-3 py-2 text-ink transition-colors hover:border-vermilion hover:text-vermilion"
                      >
                        Generate · random 20
                      </button>
                      <button
                        onClick={() => setPw(randomPassphrase())}
                        className="label border border-ink/35 px-3 py-2 text-ink transition-colors hover:border-vermilion hover:text-vermilion"
                      >
                        Generate · passphrase ×8
                      </button>
                      <button
                        onClick={() => setPw("")}
                        className="label border border-transparent px-3 py-2 text-fiber transition-colors hover:text-vermilion"
                      >
                        Clear
                      </button>
                    </div>
                  </div>

                  <div
                    key={`${a.verdict}-${profile}`}
                    className={`stamp anim-slam shrink-0 self-start text-center ${VERDICT_COLOR[a.verdict]} sm:mt-6`}
                    role="status"
                    aria-label={`verdict ${a.verdict}`}
                  >
                    <div className="text-[clamp(1.45rem,3.2vw,2rem)] leading-none">{a.verdict}</div>
                    <div className="mt-1.5 font-mono text-[8.5px] font-medium tracking-[0.22em] uppercase">
                      policy verdict
                    </div>
                  </div>
                </div>
              </div>

              {/* meter */}
              <div className="px-5 pb-5">
                <div className="flex items-baseline justify-between">
                  <span className="label text-fiber">Strength index</span>
                  <span className="font-mono text-[13px] tabular-nums">
                    {empty ? "—" : a.score}
                    <span className="text-fiber">/100</span>
                  </span>
                </div>
                <div className="mt-2 flex h-3.5 gap-[2px]" aria-hidden>
                  {Array.from({ length: SEGMENTS }).map((_, i) => {
                    const on = !empty && i < Math.round((a.score / 100) * SEGMENTS);
                    return (
                      <span
                        key={i}
                        className={`flex-1 transition-colors duration-300 ${on ? fill : "bg-ink/12"}`}
                      />
                    );
                  })}
                </div>
                <div className="relative mt-1.5 h-4 font-mono text-[10px] text-fiber">
                  <span className="absolute left-0">0</span>
                  <span
                    className="absolute -translate-x-1/2"
                    style={{ left: `${(floor / 120) * 100}%` }}
                  >
                    ▲ {floor} b
                  </span>
                  <span className="absolute right-0">120 b</span>
                </div>
              </div>

              {/* rules */}
              {empty ? (
                <div className="m-5 border border-dashed border-ink/35 px-5 py-10 text-center">
                  <div className="label text-fiber">No specimen loaded</div>
                  <p className="mx-auto mt-3 max-w-[42ch] text-[14px] leading-[1.65] text-ink/70">
                    Enter a value above or generate one. Analysis runs entirely on this page —
                    exactly as the Python CLI runs offline, with no network calls and no plaintext
                    written to disk.
                  </p>
                </div>
              ) : (
                <div className="divide-y divide-ink/15 border-t border-ink/30">
                  {a.rules.map((r) => (
                    <RuleRow key={r.id} {...r} />
                  ))}
                </div>
              )}

              {a.isPassphrase && !empty && (
                <div className="border-t border-ink/20 px-5 py-3.5 font-mono text-[11.5px] leading-[1.6] text-fiber">
                  Char-pool model reads this as {a.raw.toFixed(0)} bits because it assumes
                  independent random characters. Word-count model is the honest one:{" "}
                  {a.adjusted.toFixed(1)} bits.
                </div>
              )}
            </div>
          </Reveal>

          {/* ------------------------------ carbon copy ------------------------------ */}
          <Reveal delay={90}>
            <div className="relative border border-ink/25 bg-copy text-prussiandk shadow-[8px_10px_0_rgba(26,28,26,0.10)] lg:-rotate-[0.4deg]">
              <div className="label flex items-center justify-between border-b border-prussiandk/30 px-5 py-3 text-prussiandk/70 sm:px-6">
                <span>Carbon copy · live readout</span>
                <span className="font-mono normal-case">--profile {profile}</span>
              </div>

              {empty ? (
                <div className="px-5 py-14 text-center sm:px-6">
                  <div className="font-mono text-[13px] tracking-[0.18em] text-prussiandk/75">
                    · · · awaiting specimen · · ·
                  </div>
                  <p className="mx-auto mt-4 max-w-[40ch] font-mono text-[11.5px] leading-[1.7] text-prussiandk/80">
                    Readout will print: character pool, raw entropy, every penalty applied, the
                    adjusted figure, three crack-time vectors, the SHA-256 digest with its salt,
                    and up to five recommendations.
                  </p>
                </div>
              ) : (
                <div className="px-5 py-5 sm:px-6">
                  <div key={`${a.adjusted}-${profile}`} className="anim-feed space-y-2.5">
                    <Leader k="character pool" v={`${a.pool} symbols`} />
                    <Leader k="raw entropy" v={`${a.raw.toFixed(1)} bits`} />
                    {a.penalties.map((p, i) => (
                      <Leader
                        key={i}
                        k={`penalty ×${p.factor}`}
                        v={p.reason}
                      />
                    ))}
                    <div className="mt-4 border-t border-prussiandk/25 pt-3">
                      <Leader k="adjusted entropy" v={`${a.adjusted.toFixed(1)} bits`} strong />
                    </div>
                    <Leader k="verdict" v={`${a.verdict} · score ${a.score}/100`} strong />
                  </div>

                  {/* crack times */}
                  <div className="mt-6 border-t border-prussiandk/25 pt-4">
                    <div className="label text-prussiandk/70">
                      Time to exhaust half the keyspace
                    </div>
                    <table className="mt-3 w-full border-collapse">
                      <tbody>
                        {a.crack.map((c) => (
                          <tr key={c.label} className="border-b border-dashed border-prussiandk/25">
                            <td className="py-2 pr-3 align-top">
                              <div className="text-[13px] leading-tight">{c.label}</div>
                              <div className="font-mono text-[10.5px] text-prussiandk/75">
                                {c.rate}
                              </div>
                            </td>
                            <td className="py-2 text-right align-top font-mono text-[13px] font-medium tabular-nums">
                              {formatDuration(c.seconds)}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>

                  {/* hashing */}
                  <div className="mt-6 border-t border-prussiandk/25 pt-4">
                    <div className="flex items-baseline justify-between">
                      <span className="label text-prussiandk/70">SHA-256 digest</span>
                      <button
                        onClick={() => setSalt(makeSalt())}
                        className="label text-vermilion transition-opacity hover:opacity-70"
                      >
                        re-salt
                      </button>
                    </div>
                    <div className="mt-2 font-mono text-[12px] leading-[1.6] break-all">
                      {digest}
                    </div>

                    <div className="label mt-4 text-prussiandk/70">
                      salted · sha256(salt ‖ pw)
                    </div>
                    <div className="mt-1.5 font-mono text-[11px] break-all text-prussiandk/70">
                      salt {salt}
                    </div>
                    <div className="font-mono text-[12px] leading-[1.6] break-all">
                      {salted}
                    </div>

                    <div className="mt-3 font-mono text-[11.5px] text-prussiandk/85">
                      avalanche · 1 char changed → {av?.changed}/{av?.total} hex digits differ
                    </div>

                    <p className="mt-4 border-l-2 border-vermilion pl-3 text-[12.5px] leading-[1.6] text-prussiandk/80">
                      Demonstration only. A fast digest is not a password hash — store with
                      argon2id or bcrypt (cost ≥ 12), a unique salt per user, never bare SHA-256.
                    </p>
                  </div>

                  {/* recommendations */}
                  <div className="mt-6 border-t border-prussiandk/25 pt-4">
                    <div className="label text-prussiandk/70">
                      Recommendations · {a.recommendations.length}
                    </div>
                    <ol className="mt-3 space-y-3">
                      {a.recommendations.map((r) => (
                        <li key={r.id} className="flex gap-3">
                          <span
                            className={`label mt-[3px] shrink-0 ${
                              r.severity === "critical"
                                ? "text-vermilion"
                                : r.severity === "high"
                                  ? "text-[#8a5e0f]"
                                  : "text-prussiandk/80"
                            }`}
                          >
                            {r.id}
                          </span>
                          <span className="text-[13px] leading-[1.6] text-prussiandk/90">
                            {r.text}
                          </span>
                        </li>
                      ))}
                    </ol>
                  </div>
                </div>
              )}
            </div>
          </Reveal>
        </div>
      </div>
    </section>
  );
}
