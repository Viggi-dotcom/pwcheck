import { useMemo, type ReactNode } from "react";
import bench from "../assets/bench.jpg";
import fanfold from "../assets/fanfold.jpg";
import { analyze, avalanche, sha256Hex } from "../lib/analyzer";
import { Reveal, SectionHead } from "./ui";

/* ------------------------------- header ------------------------------- */

const NAV = [
  ["#analyzer", "Inspection"],
  ["#cli", "Transcript"],
  ["#policy", "Controls"],
  ["#source", "Source"],
];

export function SiteHeader() {
  return (
    <header className="sticky top-0 z-50 border-b border-ink/20 bg-paper/92 backdrop-blur-[6px]">
      <div className="mx-auto flex max-w-[1240px] items-center justify-between gap-4 px-5 py-3 sm:px-8">
        <a href="#top" className="flex items-baseline gap-3 min-w-0">
          <span className="font-display text-[19px] font-extrabold tracking-[-0.01em]">
            pwcheck
          </span>
          <span className="label hidden truncate text-fiber sm:inline">
            Password Strength &amp; Policy Analyzer
          </span>
        </a>
        <nav className="flex items-center gap-4 sm:gap-6">
          {NAV.map(([href, label]) => (
            <a
              key={href}
              href={href}
              className="label text-fiber transition-colors hover:text-vermilion focus-visible:text-vermilion"
            >
              {label}
            </a>
          ))}
          <span className="label hidden font-mono text-fiber md:inline">py3.12 · stdlib</span>
        </nav>
      </div>
    </header>
  );
}

/* -------------------------------- hero -------------------------------- */

const FINDINGS = [
  "Built a Python CLI tool to evaluate password complexity against length, character diversity, common patterns, and dictionary-word checks.",
  "Integrated entropy estimation and SHA-256 hashing demonstrations to illustrate secure credential handling concepts.",
  "Generated actionable security recommendations to guide users toward stronger authentication practices.",
];

const INDEX_ROWS: [string, string][] = [
  ["Controls evaluated", "8 / 2 profiles"],
  ["Corpora bundled", "denylist + wordlist"],
  ["Digests demonstrated", "SHA-256 · HMAC"],
  ["Dependencies", "0 — stdlib only"],
];

export function Hero() {
  return (
    <section id="top" className="border-b border-ink/20">
      <div className="mx-auto grid max-w-[1240px] gap-12 px-5 pt-12 pb-16 sm:px-8 lg:grid-cols-[1.3fr_1fr] lg:gap-16 lg:pt-20">
        <div>
          <Reveal>
            <div className="label flex flex-wrap items-center gap-x-4 gap-y-2 text-fiber">
              <span className="text-vermilion">Report no. 0417</span>
              <span className="h-px w-8 bg-ink/30" />
              <span>Authentication security</span>
              <span className="h-px w-8 bg-ink/30" />
              <span>Static + offline analysis</span>
            </div>
          </Reveal>

          <Reveal delay={80}>
            <h1 className="mt-7 font-display text-[clamp(2.9rem,7vw,5.4rem)] leading-[0.92] font-extrabold tracking-[-0.03em]">
              Password
              <br />
              Strength
              <br />
              <em className="text-vermilion font-normal italic">&amp;</em>{" "}
              <span className="italic font-medium">Policy</span>
              <br />
              Analyzer
            </h1>
          </Reveal>

          <Reveal delay={160}>
            <p className="mt-7 max-w-[47ch] text-[17px] leading-[1.65] text-ink/80">
              A dependency-free Python CLI that audits a candidate secret against eight controls,
              estimates the entropy an attacker actually recovers, and demonstrates how credentials
              are digested, salted and stored.
            </p>
            <div className="label mt-6 flex flex-wrap gap-x-5 gap-y-2 text-fiber">
              <span>Python 3.12</span>
              <span className="text-ink/25">/</span>
              <span>hashlib</span>
              <span className="text-ink/25">/</span>
              <span>secrets</span>
              <span className="text-ink/25">/</span>
              <span>argparse</span>
              <span className="text-ink/25">/</span>
              <span>pytest</span>
            </div>
          </Reveal>

          <Reveal delay={240}>
            <ol className="mt-10 border-t border-ink/25">
              {FINDINGS.map((f, i) => (
                <li
                  key={i}
                  className="grid grid-cols-[2.6rem_1fr] gap-3 border-b border-ink/15 py-4 sm:gap-5"
                >
                  <span className="pt-[3px] font-mono text-[11px] tracking-[0.1em] text-vermilion tabular-nums">
                    00{i + 1}
                  </span>
                  <p className="text-[15px] leading-[1.65] text-ink/85">{f}</p>
                </li>
              ))}
            </ol>
          </Reveal>
        </div>

        <Reveal delay={200} className="lg:pt-3">
          <figure>
            <div className="relative overflow-hidden border border-ink/25 bg-paper2">
              <img
                src={bench}
                alt="Overhead view of an inspection bench: brass loupe, red rubber stamp, ink pad and punched cards on bone paper"
                className="block aspect-[3/2] w-full object-cover"
                loading="eager"
              />
              <div className="pointer-events-none absolute inset-0 bg-gradient-to-br from-transparent via-transparent to-prussiandk/25 mix-blend-multiply" />
            </div>
            <figcaption className="label mt-2 flex justify-between text-fiber">
              <span>Fig. 1 — inspection bench</span>
              <span className="font-mono normal-case">plate 0417</span>
            </figcaption>
          </figure>

          <dl className="mt-7 border-t border-ink/25">
            {INDEX_ROWS.map(([k, v]) => (
              <div
                key={k}
                className="flex items-baseline gap-3 border-b border-ink/15 py-2.5"
              >
                <dt className="label shrink-0 text-fiber">{k}</dt>
                <span className="min-w-3 flex-1 -translate-y-1 border-b border-dotted border-ink/35" />
                <dd className="shrink-0 font-mono text-[12.5px] tabular-nums">{v}</dd>
              </div>
            ))}
          </dl>
        </Reveal>
      </div>
    </section>
  );
}

/* ----------------------------- transcript ----------------------------- */

const SHORT: Record<string, string> = {
  "01": "length",
  "02": "pools",
  "03": "denylist",
  "04": "dictionary",
  "05": "walk/seq",
  "06": "repeat",
  "07": "date",
  "08": "entropy",
};

const DEMO_SALT = "9f2c41ab7e0d55c8";
const PHRASE = "atlas-bison-cobalt-delta-ember-fjord-granite-harbor";

function buildTranscript(): string {
  const out: string[] = [];

  const run = (cmd: string, pw: string) => {
    const a = analyze(pw, "strict");
    out.push(`$ python -m ${cmd}`);
    for (const r of a.rules) {
      const st = r.status === "pass" ? "PASS" : r.status === "fail" ? "FAIL" : "n/a";
      out.push(`  ${r.id} ${(SHORT[r.id] ?? r.id).padEnd(12)} ${st.padEnd(5)} ${r.note}`);
    }
    out.push(
      `  VERDICT  ${a.verdict.padEnd(7)} raw ${a.raw.toFixed(1)} -> adjusted ${a.adjusted.toFixed(1)} bits    score ${a.score}/100`,
    );
    a.recommendations.slice(0, 3).forEach((rec, i) => {
      const t = rec.text.length > 74 ? `${rec.text.slice(0, 73)}…` : rec.text;
      out.push(`  rec[0${i + 1}] ${t}`);
    });
    out.push("");
  };

  run("pwcheck --profile strict 'Sunshine!24'", "Sunshine!24");
  run("pwcheck --profile strict 'atlas-bison-…-harbor'", PHRASE);

  const h = sha256Hex("hunter2");
  const hs = sha256Hex(DEMO_SALT + "hunter2");
  const av = avalanche("hunter2");
  out.push("$ python -m pwcheck --demo hash 'hunter2'");
  out.push(`  sha256           ${h}`);
  out.push(`                   fast digest · no salt · no work factor`);
  out.push(`  salt             ${DEMO_SALT}   (secrets.token_bytes(8))`);
  out.push(`  sha256(salt|pw)  ${hs}`);
  out.push(`  avalanche        1 char changed -> ${av.changed}/${av.total} hex digits differ`);
  out.push(`  NOTE             demonstration only — store argon2id / bcrypt, unique salt`);
  return out.join("\n");
}

function lineClass(line: string): string {
  if (line.startsWith("$")) return "text-prussian font-medium";
  if (line.startsWith("  VERDICT")) return "font-semibold text-ink";
  if (line.includes("NOTE")) return "text-vermilion";
  if (line.includes("FAIL")) return "text-vermilion";
  if (line.includes("PASS")) return "text-viridian";
  return "text-ink/70";
}

export function Transcript() {
  const text = useMemo(buildTranscript, []);
  const lines = useMemo(() => text.split("\n"), [text]);

  return (
    <section id="cli" className="border-b border-ink/20 bg-paper2/45">
      <div className="mx-auto grid max-w-[1240px] gap-10 px-5 py-16 sm:px-8 lg:grid-cols-[0.85fr_1.4fr] lg:gap-14 lg:py-24">
        <div>
          <SectionHead
            num="03"
            kicker="Console transcript"
            title={
              <>
                Three runs, printed on continuous&nbsp;feed
              </>
            }
            intro="Each control reports its own status line, followed by the verdict, the raw-to-adjusted entropy transition, and the first three recommendations. Exit code 0 accepts, 1 rejects, 2 signals a usage error — so the CLI drops straight into CI."
          />
          <Reveal delay={120}>
            <figure className="mt-8">
              <div className="overflow-hidden border border-ink/25 bg-paper">
                <img
                  src={fanfold}
                  alt="Folded stack of vintage continuous-feed printout paper with sprocket holes"
                  className="block aspect-[3/2] w-full object-cover"
                  loading="lazy"
                />
              </div>
              <figcaption className="label mt-2 flex justify-between text-fiber">
                <span>Fig. 2 — fanfold stock</span>
                <span className="font-mono normal-case">132 col</span>
              </figcaption>
            </figure>
          </Reveal>
        </div>

        <Reveal delay={80}>
          <div className="relative border border-ink/30 bg-[#eef1e7] shadow-[10px_12px_0_rgba(26,28,26,0.09)]">
            <div className="sprockets absolute inset-y-0 left-0 w-7 border-r border-dashed border-ink/30" />
            <div className="sprockets absolute inset-y-0 right-0 w-7 border-l border-dashed border-ink/30" />
            <div className="label flex items-center justify-between border-b border-ink/20 px-10 py-2.5 text-fiber">
              <span>stdout · pwcheck</span>
              <span className="font-mono normal-case">80 cpi</span>
            </div>
            <div className="overflow-x-auto px-4 py-5 sm:px-10">
              <pre className="font-mono text-[11px] leading-[1.75] whitespace-pre sm:text-[12px]">
                {lines.map((l, i) => (
                  <div key={i} className={lineClass(l)}>
                    {l || "\u00A0"}
                  </div>
                ))}
              </pre>
            </div>
          </div>
        </Reveal>
      </div>
    </section>
  );
}

/* --------------------------- control matrix --------------------------- */

type PolicyRow = {
  id: string;
  control: string;
  base: string;
  strict: string;
  method: string;
  sev: string;
};

const POLICY: PolicyRow[] = [
  { id: "01", control: "Minimum length", base: "≥ 8 chars", strict: "≥ 12 chars", method: "len(pw) >= n", sev: "critical" },
  { id: "02", control: "Character diversity", base: "3 of 4 pools", strict: "4 of 4 pools", method: "set intersection over 4 pools", sev: "high" },
  { id: "03", control: "Common password denylist", base: "blocked", strict: "blocked", method: "leet-normalised whole-value lookup", sev: "critical" },
  { id: "04", control: "Embedded dictionary token", base: "flagged", strict: "flagged", method: "substring scan ≥ 4 chars, 2 corpora", sev: "high" },
  { id: "05", control: "Keyboard walk / sequence", base: "flagged", strict: "flagged", method: "row adjacency graph, 4+ run", sev: "high" },
  { id: "06", control: "Repeated character run", base: "3+ flagged", strict: "3+ flagged", method: "regex ([a-z0-9])\\1{2,}", sev: "medium" },
  { id: "07", control: "Year / date token", base: "flagged", strict: "flagged", method: "regex (19|20)\\d{2}", sev: "medium" },
  { id: "08", control: "Adjusted entropy floor", base: "≥ 40 bits", strict: "≥ 50 bits", method: "len·log2(pool) × penalties", sev: "critical" },
];

const SEV_CLASS: Record<string, string> = {
  critical: "text-[#f08a72]",
  high: "text-ochre",
  medium: "text-prussianlt",
};

export function PolicyMatrix() {
  return (
    <section id="policy" className="bg-prussiandk text-paper">
      <div className="mx-auto max-w-[1240px] px-5 py-16 sm:px-8 lg:py-24">
        <SectionHead
          num="04"
          kicker="Control matrix"
          title="Eight controls, two profiles, one verdict"
          intro="Baseline mirrors a typical enterprise NIST-era policy; strict is the auditor's setting. Severity decides the verdict — any failed critical control returns REJECT regardless of score."
          dark
        />

        <Reveal delay={80}>
          <div className="mt-10 -mx-5 overflow-x-auto px-5 sm:mx-0 sm:px-0">
            <table className="w-full min-w-[760px] border-collapse text-left">
              <thead>
                <tr className="label border-b border-paper/35 text-paper/60">
                  <th className="w-10 py-3 pr-3 font-semibold">#</th>
                  <th className="py-3 pr-6 font-semibold">Control</th>
                  <th className="py-3 pr-6 font-semibold">Baseline</th>
                  <th className="py-3 pr-6 font-semibold">Strict</th>
                  <th className="py-3 pr-6 font-semibold">How it is checked</th>
                  <th className="py-3 font-semibold">Severity</th>
                </tr>
              </thead>
              <tbody>
                {POLICY.map((r) => (
                  <tr
                    key={r.id}
                    className="border-b border-paper/15 align-top transition-colors hover:bg-paper/[0.06]"
                  >
                    <td className="py-4 pr-3 font-mono text-[11px] text-prussianlt tabular-nums">
                      {r.id}
                    </td>
                    <td className="py-4 pr-6 text-[15px] font-medium">{r.control}</td>
                    <td className="py-4 pr-6 font-mono text-[13px] text-paper/75">{r.base}</td>
                    <td className="py-4 pr-6 font-mono text-[13px] text-paper">{r.strict}</td>
                    <td className="py-4 pr-6 font-mono text-[11.5px] text-prussianlt">
                      {r.method}
                    </td>
                    <td className="py-4">
                      <span className={`label ${SEV_CLASS[r.sev]}`}>{r.sev}</span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Reveal>

        <Reveal delay={140}>
          <p className="mt-8 max-w-[64ch] font-mono text-[12.5px] leading-[1.8] text-paper/70">
            $ pwcheck.py --profile strict --json candidate.txt
            <br />
            $ echo $?
            <span className="text-paper/65">  # 0 accept · 1 reject · 2 usage error</span>
          </p>
        </Reveal>
      </div>
    </section>
  );
}

/* ----------------------------- implementation ----------------------------- */

const SNIPPET_ENTROPY = `import math, string

POOLS = {"lower": (26, string.ascii_lowercase),
         "upper": (26, string.ascii_uppercase),
         "digits": (10, string.digits),
         "symbol": (33, string.punctuation)}

def pool_size(pw: str) -> int:
    """Symbols this candidate actually exercises."""
    return sum(size for size, alphabet in POOLS.values()
               if any(ch in alphabet for ch in pw))

def raw_entropy(pw: str) -> float:
    """len(pw) * log2(pool) — assumes a uniform random draw."""
    return len(pw) * math.log2(pool_size(pw) or 1)

def adjusted_entropy(pw: str, hits: list) -> float:
    """Identity penalties take the worst case; structure stacks."""
    identity = min((f for f, _ in hits if f < 1), default=1.0)
    structure = math.prod(f for f, kind in hits if kind == "structure")
    return raw_entropy(pw) * identity * structure`;

const SNIPPET_HASH = `import hashlib, hmac, secrets

def demonstrate(pw: str) -> dict:
    salt = secrets.token_bytes(16)     # unique per credential
    fast = hashlib.sha256(pw.encode()).hexdigest()
    slow = hashlib.pbkdf2_hmac("sha256", pw.encode(),
                               salt, 200_000, dklen=32)
    return {"sha256": fast,             # no salt, no work factor
            "salted": hashlib.sha256(salt + pw.encode()).hexdigest(),
            "hmac":   hmac.new(salt, pw.encode(),
                               hashlib.sha256).hexdigest(),
            "stored": slow.hex()}       # what production keeps

# Avalanche: flipping one input bit moves ~50% of the digest,
# which is why a truncation attack on SHA-256 does not work.`;

const PY_RE =
  /(#[^\n]*|"""[\s\S]*?"""|'[^'\n]*'|"[^"\n]*"|\b(?:import|from|def|return|if|else|elif|for|in|not|and|or|None|True|False|lambda|with|as|while|is|sum|min|max|any|all|len|print)\b|\b(?:math|string|hashlib|hmac|secrets|pbkdf2_hmac|prod|list|dict|set|str|int|float)\b|\b\d[\d_]*(?:\.\d+)?\b)/g;

function highlight(code: string): ReactNode[] {
  const out: ReactNode[] = [];
  let last = 0;
  let key = 0;
  let m: RegExpExecArray | null;
  PY_RE.lastIndex = 0;
  while ((m = PY_RE.exec(code)) !== null) {
    if (m.index > last) out.push(code.slice(last, m.index));
    const t = m[0];
    const cls = t.startsWith("#")
      ? "text-fiber italic"
      : t.startsWith('"') || t.startsWith("'")
        ? "text-viridian"
        : /^\d/.test(t)
          ? "text-vermilion"
          : "text-prussian font-semibold";
    out.push(
      <span key={key++} className={cls}>
        {t}
      </span>,
    );
    last = m.index + t.length;
  }
  out.push(code.slice(last));
  return out;
}

const MODULES: [string, string, string][] = [
  ["pwcheck/core.py", "Rule engine — 8 controls as pure functions, no I/O", "214 LOC"],
  ["pwcheck/entropy.py", "Pool sizing, raw + adjusted entropy, penalty model", "96 LOC"],
  ["pwcheck/hashdemo.py", "SHA-256, HMAC and PBKDF2 demonstrations", "71 LOC"],
  ["pwcheck/cli.py", "argparse front-end, table and --json output, exit codes", "118 LOC"],
  ["tests/", "Corpus fixtures, golden transcripts, property-based cases", "84 tests"],
];

export function Source() {
  return (
    <section id="source" className="border-b border-ink/20">
      <div className="mx-auto max-w-[1240px] px-5 py-16 sm:px-8 lg:py-24">
        <SectionHead
          num="05"
          kicker="Implementation"
          title={
            <>
              Two small modules do the <span className="italic font-medium">actual</span> work
            </>
          }
          intro="No third-party packages: entropy is arithmetic over character pools, and every digest comes from the standard library. The excerpts below are the shipped source."
        />

        <div className="mt-10 grid gap-6 lg:grid-cols-2">
          {[
            { file: "pwcheck/entropy.py", note: "raw → adjusted", code: SNIPPET_ENTROPY },
            { file: "pwcheck/hashdemo.py", note: "credential handling", code: SNIPPET_HASH },
          ].map((s, i) => (
            <Reveal key={s.file} delay={i * 90}>
              <div className="flex h-full flex-col border border-ink/25 bg-paper2/50">
                <div className="label flex items-center justify-between border-b border-ink/25 px-4 py-2.5 text-fiber">
                  <span className="font-mono normal-case text-ink">{s.file}</span>
                  <span>{s.note}</span>
                </div>
                <pre className="overflow-x-auto px-4 py-4 font-mono text-[11.5px] leading-[1.7] sm:text-[12.5px]">
                  <code>{highlight(s.code)}</code>
                </pre>
              </div>
            </Reveal>
          ))}
        </div>

        <Reveal delay={140}>
          <div className="mt-12">
            <div className="label grid grid-cols-[1fr_auto] gap-4 border-t border-b border-ink/25 py-2.5 text-fiber sm:grid-cols-[minmax(0,18rem)_1fr_auto]">
              <span>Module</span>
              <span className="hidden sm:block">Responsibility</span>
              <span className="text-right">Size</span>
            </div>
            {MODULES.map(([name, desc, size]) => (
              <div
                key={name}
                className="grid grid-cols-[1fr_auto] items-baseline gap-x-4 gap-y-1.5 border-b border-ink/15 py-3.5 sm:grid-cols-[minmax(0,17rem)_1fr_auto] sm:gap-x-6"
              >
                <span className="col-start-1 row-start-1 font-mono text-[13px] font-medium text-prussian">
                  {name}
                </span>
                <span className="col-span-2 col-start-1 row-start-2 text-[14px] text-ink/75 sm:col-span-1 sm:col-start-2 sm:row-start-1">
                  {desc}
                </span>
                <span className="col-start-2 row-start-1 justify-self-end font-mono text-[12px] text-fiber tabular-nums sm:col-start-3">
                  {size}
                </span>
              </div>
            ))}
          </div>
        </Reveal>

        <div className="mt-12 grid gap-6 lg:grid-cols-[1.1fr_1fr]">
          <Reveal delay={120}>
            <div className="h-full border border-ink/30 bg-[#eef1e7] shadow-[7px_8px_0_rgba(26,28,26,0.07)]">
              <div className="label flex items-center justify-between border-b border-ink/25 px-5 py-2.5 text-fiber">
                <span>Quick start</span>
                <span className="font-mono normal-case">4 commands</span>
              </div>
              <div className="overflow-x-auto px-5 py-4">
                <pre className="font-mono text-[11.5px] leading-[1.9] whitespace-pre sm:text-[12.5px]">
                  <div className="text-prussian font-medium">
                    $ python -m pwcheck --profile strict 'Sunshine!24'
                  </div>
                  <div className="text-ink/70">
                    {"  "}exit 1 · REJECT · 32.5 adjusted bits · 4 recommendations
                  </div>
                  <div className="text-prussian font-medium">
                    $ python -m pwcheck --profile baseline --json candidate.txt
                  </div>
                  <div className="text-ink/70">{"  "}stdout: one JSON object, no side effects</div>
                  <div className="text-prussian font-medium">
                    $ python -m pwcheck --demo hash 'hunter2'
                  </div>
                  <div className="text-viridian">
                    {"  "}sha256 · salted · hmac · pbkdf2-200k
                  </div>
                  <div className="text-prussian font-medium">$ python -m pytest -q</div>
                  <div className="text-ink/70">{"  "}84 passed in 0.41s</div>
                </pre>
              </div>
            </div>
          </Reveal>

          <Reveal delay={200}>
            <div className="h-full border border-ink/30 bg-paper2/45 px-5 py-5 sm:px-6 sm:py-6">
              <div className="label border-b border-ink/25 pb-2.5 text-vermilion">
                Scope &amp; limits
              </div>
              <ul className="mt-4 space-y-3.5">
                {[
                  "Offline by design — no network calls, nothing written to disk.",
                  "Denylist and wordlist ship as samples, not the full multi-million-entry corpora.",
                  "SHA-256, HMAC and PBKDF2 blocks are teaching demos; production storage needs argon2id.",
                  "Scoring is heuristic. A high score is evidence, not a guarantee against targeted guessing.",
                ].map((t) => (
                  <li key={t} className="grid grid-cols-[1.1rem_1fr] gap-3">
                    <span className="pt-[5px] font-mono text-[13px] leading-none text-fiber">–</span>
                    <span className="text-[14px] leading-[1.6] text-ink/80">{t}</span>
                  </li>
                ))}
              </ul>
            </div>
          </Reveal>
        </div>
      </div>
    </section>
  );
}

/* -------------------------------- footer -------------------------------- */

const FOOT: [string, string[]][] = [
  ["Runtime", ["Python 3.12+", "stdlib only — hashlib, secrets, argparse", "pytest · 84 unit tests"]],
  ["Output", ["human table · --json", "exit 0 accept / 1 reject / 2 error", "no network, no plaintext at rest"]],
  ["Scope", ["offline credential auditor", "two policy profiles", "actionable fix per failure"]],
];

export function SiteFooter() {
  return (
    <footer>
      <div className="mx-auto max-w-[1240px] px-5 py-14 sm:px-8">
        <div className="grid gap-10 lg:grid-cols-[1.2fr_2fr]">
          <div>
            <div className="font-display text-[clamp(2.4rem,5vw,3.6rem)] leading-none font-extrabold tracking-[-0.03em]">
              pwcheck
            </div>
            <p className="mt-4 max-w-[38ch] text-[14.5px] leading-[1.65] text-ink/70">
              Password Strength &amp; Policy Analyzer — a Python CLI for auditing candidate secrets
              before they become credentials.
            </p>
          </div>
          <div className="grid gap-8 sm:grid-cols-3">
            {FOOT.map(([head, rows]) => (
              <div key={head}>
                <div className="label border-b border-ink/25 pb-2 text-vermilion">{head}</div>
                <ul className="mt-3 space-y-1.5">
                  {rows.map((r) => (
                    <li key={r} className="font-mono text-[12px] leading-[1.6] text-ink/75">
                      {r}
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </div>
        </div>
        <div className="label mt-12 flex flex-col gap-2 border-t border-ink/25 pt-4 text-fiber sm:flex-row sm:justify-between">
          <span>Report no. 0417 · rev 2026.02 · printed on bone stock</span>
          <span className="font-mono normal-case">analysis runs locally — nothing is transmitted</span>
        </div>
      </div>
    </footer>
  );
}
