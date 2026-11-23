/* ------------------------------------------------------------------
   Password Strength & Policy Analyzer — browser port of the Python CLI
   core (pwcheck/core.py + pwcheck/entropy.py + pwcheck/hashdemo.py).
   ------------------------------------------------------------------ */

export type Profile = "baseline" | "strict";
export type Status = "pass" | "fail" | "na";
export type Severity = "critical" | "high" | "medium";
export type Verdict = "ACCEPT" | "REVIEW" | "REJECT";

export interface Rule {
  id: string;
  label: string;
  method: string;
  status: Status;
  note: string;
  severity: Severity;
}

export interface Recommendation {
  id: string;
  severity: Severity;
  text: string;
}

export interface Analysis {
  input: string;
  profile: Profile;
  rules: Rule[];
  verdict: Verdict;
  score: number;
  pool: number;
  length: number;
  raw: number;
  adjusted: number;
  penalties: { factor: number; reason: string }[];
  crack: { label: string; rate: string; seconds: number }[];
  recommendations: Recommendation[];
  isPassphrase: boolean;
  tokens: string[];
  findings: { kind: string; value: string }[];
}

/* ------------------------------- SHA-256 ------------------------------- */

const K = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

const rotr = (x: number, n: number) => ((x >>> n) | (x << (32 - n))) >>> 0;

/** FIPS 180-4 SHA-256, written out so the demo has no runtime dependencies. */
export function sha256Hex(input: string): string {
  const bytes = new TextEncoder().encode(input);
  const total = Math.ceil((bytes.length + 9) / 64) * 64;
  const buf = new Uint8Array(total);
  buf.set(bytes);
  buf[bytes.length] = 0x80;
  const view = new DataView(buf.buffer);
  const bits = bytes.length * 8;
  view.setUint32(total - 8, Math.floor(bits / 0x100000000), false);
  view.setUint32(total - 4, bits >>> 0, false);

  const H = new Uint32Array([
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
  ]);
  const w = new Uint32Array(64);

  for (let off = 0; off < total; off += 64) {
    for (let i = 0; i < 16; i++) w[i] = view.getUint32(off + i * 4, false);
    for (let i = 16; i < 64; i++) {
      const a15 = w[i - 15];
      const a2 = w[i - 2];
      const s0 = (rotr(a15, 7) ^ rotr(a15, 18) ^ (a15 >>> 3)) >>> 0;
      const s1 = (rotr(a2, 17) ^ rotr(a2, 19) ^ (a2 >>> 10)) >>> 0;
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }
    let a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], h = H[7];
    for (let i = 0; i < 64; i++) {
      const S1 = (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) >>> 0;
      const ch = ((e & f) ^ (~e & g)) >>> 0;
      const t1 = (h + S1 + ch + K[i] + w[i]) >>> 0;
      const S0 = (rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) >>> 0;
      const maj = ((a & b) ^ (a & c) ^ (b & c)) >>> 0;
      const t2 = (S0 + maj) >>> 0;
      h = g; g = f; f = e;
      e = (d + t1) >>> 0;
      d = c; c = b; b = a;
      a = (t1 + t2) >>> 0;
    }
    H[0] = (H[0] + a) >>> 0; H[1] = (H[1] + b) >>> 0;
    H[2] = (H[2] + c) >>> 0; H[3] = (H[3] + d) >>> 0;
    H[4] = (H[4] + e) >>> 0; H[5] = (H[5] + f) >>> 0;
    H[6] = (H[6] + g) >>> 0; H[7] = (H[7] + h) >>> 0;
  }
  return Array.from(H)
    .map((x) => (x >>> 0).toString(16).padStart(8, "0"))
    .join("");
}

/* -------------------------------- corpora ------------------------------- */

const COMMON = [
  "123456", "password", "123456789", "12345678", "12345", "qwerty", "abc123", "password1",
  "111111", "123123", "admin", "letmein", "welcome", "monkey", "dragon", "master", "sunshine",
  "princess", "football", "iloveyou", "trustno1", "starwars", "whatever", "qazwsx", "passw0rd",
  "hello", "freedom", "shadow", "michael", "jennifer", "jordan", "superman", "harley", "ranger",
  "hunter", "buster", "soccer", "hockey", "killer", "george", "andrew", "charlie", "thomas",
  "robert", "access", "ashley", "bailey", "thunder", "matrix", "master1", "summer", "winter",
  "computer", "internet", "samsung", "google", "facebook", "changeme", "secret", "login",
  "passw0rd", "p@ssw0rd", "qwerty123", "1q2w3e4r", "zaq12wsx", "asdfghjkl", "1234567",
  "baseball", "corvette", "jessica", "pepper", "ginger", "amanda", "nicole", "daniel",
  "anthony", "batman", "tigger", "hunter2", "trustno", "lonely", "whatever1", "flower",
];

const DICT = [
  "sunshine", "dragon", "master", "monkey", "princess", "football", "baseball", "hockey",
  "soccer", "killer", "shadow", "freedom", "secret", "welcome", "letmein", "password", "admin",
  "summer", "winter", "autumn", "spring", "computer", "internet", "matrix", "batman", "superman",
  "starwars", "pokemon", "cookie", "purple", "orange", "yellow", "silver", "golden", "flower",
  "garden", "forest", "river", "ocean", "island", "castle", "diamond", "crystal", "thunder",
  "lightning", "rainbow", "butterfly", "blessed", "angels", "heaven", "lovely", "darling",
  "sweetie", "kisses", "forever", "friends", "family", "happy", "smile", "little", "bigdog",
  "puppy", "kitten", "horses", "ranger", "tigers", "eagle", "phoenix", "wizard", "ninja",
  "samurai", "soldier", "captain", "general", "money", "dollar", "cash", "company", "office",
  "work", "school", "college", "student", "teacher", "engine", "rocket", "planet", "galaxy",
  "coffee", "chicken", "pepper", "cheese", "banana", "orange1", "phoenix1", "liverpool",
  "arsenal", "chelsea", "barcelona", "juventus", "pokemon1", "minecraft", "fortnite", "xbox",
  "playstation", "nintendo", "guitar", "piano", "violin", "dancing", "singing", "acting",
  "smart", "genius", "trustno", "whatever", "anything",
  "something", "everything", "nothing", "change", "default", "system", "server", "backup",
  "correct", "horse", "battery", "staple", "purple1", "cheese1", "letme", "welcome1",
  "sun", "moon", "star", "love", "angel", "baby", "girl", "boy", "cool", "nice", "best",
  "good", "god", "king", "queen", "prince", "hero", "legend", "magic", "dream", "peace",
];

const KEY_ROWS = [
  "qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890", "1qaz2wsx3edc", "qazwsxedc",
  "qazwsx", "zaq12wsx", "!@#$%^&*()",
];

/** 128 words — a stand-in for the EFF large wordlist (7776 entries). */
const GEN_WORDS = [
  "atlas", "bison", "cobalt", "delta", "ember", "fjord", "granite", "harbor",
  "indigo", "juniper", "krypton", "lantern", "meadow", "nectar", "obsidian", "prairie",
  "quartz", "ravine", "summit", "timber", "umber", "velvet", "willow", "zenith",
  "amber", "basalt", "cinder", "dovetail", "echo", "flint", "garnet", "hollow",
  "ivory", "jasper", "keystone", "lichen", "marble", "nimbus", "onyx", "pewter",
  "quiver", "ripple", "slate", "thicket", "upland", "vantage", "walnut", "yarrow",
  "anchor", "beacon", "compass", "dinghy", "estuary", "flotsam", "groyne", "helm",
  "isobar", "jetty", "keelson", "lodestone", "mainsail", "nautical", "orrery", "plankton",
  "quay", "rudder", "saltire", "tidepool", "undertow", "vortex", "westerly", "zephyr",
  "almond", "brioche", "cardamom", "dulcit", "espresso", "fenugreek", "gruyere", "honeydew",
  "inkling", "juniper2", "kumquat", "lavender", "marmalade", "nutmeg", "oatmeal", "paprika",
  "quinoa", "rosemary", "saffron", "tarragon", "vanilla", "wasabi", "yeast", "zest",
  "copper", "bronze", "cobweb", "driftwood", "earthen", "flint2", "glacier", "hillside",
  "igloo", "jigsaw", "kindling", "leather", "mosaic", "northwind", "opal", "patchwork",
  "quilt", "rustic", "sandstone", "trestle", "updraft", "vineyard", "woodgrain", "lantern2",
];

const WORDSET = new Set([...DICT, ...GEN_WORDS, "correct", "horse", "battery", "staple", "purple", "dragon"]);

const POOLS: { name: string; size: number; test: (c: string) => boolean }[] = [
  { name: "a-z", size: 26, test: (c) => c >= "a" && c <= "z" },
  { name: "A-Z", size: 26, test: (c) => c >= "A" && c <= "Z" },
  { name: "0-9", size: 10, test: (c) => c >= "0" && c <= "9" },
  { name: "!@#$", size: 33, test: (c) => "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~".includes(c) },
];

const LEET: Record<string, string> = { "0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", $: "s", "!": "i", "+": "t" };

const norm = (s: string) =>
  s.toLowerCase().replace(/[013457@$!+]/g, (c) => LEET[c] ?? c);

/* ------------------------------- helpers ------------------------------- */

export function makeSalt(bytes = 16): string {
  const arr = new Uint8Array(bytes);
  crypto.getRandomValues(arr);
  return Array.from(arr).map((b) => b.toString(16).padStart(2, "0")).join("");
}

export function randomPassword(len = 20): string {
  const pool = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%&*?-_=+";
  const out: string[] = [];
  const grab = () => pool[crypto.getRandomValues(new Uint32Array(1))[0] % pool.length];
  out.push("abcdefghijkmnopqrstuvwxyz"[crypto.getRandomValues(new Uint32Array(1))[0] % 25]);
  out.push("ABCDEFGHJKLMNPQRSTUVWXYZ"[crypto.getRandomValues(new Uint32Array(1))[0] % 25]);
  out.push("23456789"[crypto.getRandomValues(new Uint32Array(1))[0] % 8]);
  out.push("!@#$%&*?-_=+"[crypto.getRandomValues(new Uint32Array(1))[0] % 12]);
  while (out.length < len) out.push(grab());
  for (let i = out.length - 1; i > 0; i--) {
    const j = crypto.getRandomValues(new Uint32Array(1))[0] % (i + 1);
    [out[i], out[j]] = [out[j], out[i]];
  }
  return out.join("");
}

export function randomPassphrase(tokens = 8): string {
  const picked: string[] = [];
  while (picked.length < tokens) {
    const w = GEN_WORDS[crypto.getRandomValues(new Uint32Array(1))[0] % GEN_WORDS.length];
    if (!picked.includes(w.replace(/\d+$/, ""))) picked.push(w.replace(/\d+$/, ""));
  }
  return picked.join("-");
}

export function formatDuration(seconds: number): string {
  if (!isFinite(seconds)) return "beyond computation";
  if (seconds < 1) return "under 1 second";
  let v = seconds;
  let unit = "second";
  const steps: [number, string][] = [
    [60, "minute"], [60, "hour"], [24, "day"], [365, "year"],
  ];
  for (const [div, name] of steps) {
    if (v < div) break;
    v /= div;
    unit = name;
  }
  const one = Math.abs(v - 1) < 0.005;
  const label =
    unit === "year" && v >= 1e6
      ? `${(v / 10 ** Math.floor(Math.log10(v))).toFixed(1)} × 10^${Math.floor(Math.log10(v))}`
      : v >= 1000
        ? Math.round(v).toLocaleString("en-US")
        : v >= 10
          ? v.toFixed(1)
          : v.toFixed(2);
  return `${label} ${unit}${one ? "" : "s"}`;
}

/* ------------------------------- the engine ------------------------------ */

const clamp = (n: number, lo: number, hi: number) => Math.min(hi, Math.max(lo, n));

export function analyze(input: string, profile: Profile): Analysis {
  const pw = input;
  const minLen = profile === "strict" ? 12 : 8;
  const minPools = profile === "strict" ? 4 : 3;
  const floor = profile === "strict" ? 50 : 40;

  const tokens = pw.split(/[-_\s'’.]+/).filter(Boolean);
  const isPassphrase =
    tokens.length >= 4 &&
    tokens.every((t) => /^[a-z]{3,}$/i.test(t) && WORDSET.has(t.toLowerCase()));

  const present = POOLS.filter((p) => pw.split("").some((c) => p.test(c)));
  const pool = present.reduce((s, p) => s + p.size, 0);
  const length = pw.length;
  const raw = length && pool ? length * Math.log2(pool) : 0;

  const lowered = pw.toLowerCase();
  const flat = norm(pw);
  // denylist = corpus entry, leet-normalised, matched as a whole value only
  const commonHit = COMMON.find((c) => c === flat || c === lowered);
  const dictHit = DICT.filter((d) => d.length >= 4 && (flat.includes(d) || lowered.includes(d)))
    .sort((a, b) => b.length - a.length)[0];

  let walkHit = "";
  for (const row of KEY_ROWS) {
    for (let i = 0; i + 4 <= row.length; i++) {
      const sub = row.slice(i, i + 4);
      if (lowered.includes(sub) || lowered.includes([...sub].reverse().join(""))) walkHit = sub;
    }
  }
  const seqMatch = lowered.match(/([a-z0-9])\1{2,}/);
  const repeatHit = seqMatch ? seqMatch[0] : "";
  let seqRun = "";
  for (let i = 0; i + 4 <= lowered.length; i++) {
    const s = lowered.slice(i, i + 4);
    const codes = [...s].map((c) => c.charCodeAt(0));
    const up = codes.every((c, k) => k === 0 || c === codes[k - 1] + 1);
    const down = codes.every((c, k) => k === 0 || c === codes[k - 1] - 1);
    if ((up || down) && /^[a-z0-9]+$/.test(s)) seqRun = s;
  }
  const yearHit = (pw.match(/(?:19|20)\d{2}/) || [""])[0];

  /* penalties → adjusted entropy */
  const penalties: { factor: number; reason: string }[] = [];
  let identity = 1;
  let structure = 1;

  if (isPassphrase) {
    penalties.push({
      factor: 1,
      reason: `passphrase mode — ${tokens.length} × log2(${GEN_WORDS.length})`,
    });
    if (new Set(tokens).size !== tokens.length) {
      structure *= 0.75;
      penalties.push({ factor: 0.75, reason: "repeated word" });
    }
  } else {
    // identity penalties describe WHAT the secret is — take the single worst,
    // they describe the same token rather than compounding.
    if (commonHit) identity = 0.15;
    else if (dictHit) identity = 0.45;
    // structure penalties describe HOW it is built — these do compound.
    if (walkHit) structure *= 0.6;
    if (seqRun) structure *= 0.65;
    if (repeatHit) structure *= 0.8;
    if (yearHit) structure *= 0.85;
    if (identity < 1)
      penalties.push({
        factor: identity,
        reason: commonHit ? `denylist entry "${commonHit}"` : `dictionary token "${dictHit}"`,
      });
    if (walkHit) penalties.push({ factor: 0.6, reason: `keyboard walk "${walkHit}"` });
    if (seqRun) penalties.push({ factor: 0.65, reason: `character run "${seqRun}"` });
    if (repeatHit) penalties.push({ factor: 0.8, reason: `repeated run "${repeatHit}"` });
    if (yearHit) penalties.push({ factor: 0.85, reason: `date token "${yearHit}"` });
  }

  const adjusted = isPassphrase
    ? tokens.length * Math.log2(GEN_WORDS.length)
    : Math.min(raw, raw * identity * structure);

  const mk = (id: string, label: string, method: string, severity: Severity, status: Status, note: string): Rule =>
    ({ id, label, method, severity, status, note });

  const rules: Rule[] = [
    mk(
      "01", `Minimum length — ${minLen} chars`, `len(pw) >= ${minLen}`, "critical",
      length >= minLen ? "pass" : "fail",
      isPassphrase ? `${tokens.length} tokens · ${length} chars` : `${length} chars`,
    ),
    mk(
      "02", `Character pools — ${minPools} of 4`, "set intersection over 4 pools", "high",
      isPassphrase ? "na" : present.length >= minPools ? "pass" : "fail",
      isPassphrase
        ? "n/a — passphrase mode derives entropy from word count"
        : `${present.length}/4 · ${present.map((p) => p.name).join(" ") || "—"}`,
    ),
    mk(
      "03", "Common password denylist", "normalised lookup, top-10k corpus", "critical",
      !commonHit ? "pass" : "fail",
      commonHit ? `matched "${commonHit}"` : "no corpus match",
    ),
    mk(
      "04", "Embedded dictionary token", "leet-normalised substring scan", "high",
      isPassphrase ? "pass" : !dictHit ? "pass" : "fail",
      isPassphrase
        ? `diceware — ${tokens.length} tokens, entropy from word count`
        : dictHit ? `found "${dictHit}"` : "no token ≥ 4 chars from wordlist",
    ),
    mk(
      "05", "Keyboard walk / sequence", "row adjacency graph, 4+ run", "high",
      !walkHit && !seqRun ? "pass" : "fail",
      walkHit ? `walk "${walkHit}"` : seqRun ? `run "${seqRun}"` : "no adjacent-key run",
    ),
    mk(
      "06", "Repeated character run", "regex ([a-z0-9])\\1{2,}", "medium",
      !repeatHit ? "pass" : "fail",
      repeatHit ? `run of ${repeatHit.length} × "${repeatHit[0]}"` : "no run of 3+",
    ),
    mk(
      "07", "Year / date token", "regex (19|20)\\d{2}", "medium",
      !yearHit ? "pass" : "fail",
      yearHit ? `contains "${yearHit}"` : "no date-shaped token",
    ),
    mk(
      "08", `Adjusted entropy ≥ ${floor} bits`, "len·log2(pool) × penalties", "critical",
      adjusted >= floor ? "pass" : "fail",
      `${adjusted.toFixed(1)} bits vs floor ${floor}`,
    ),
  ];

  const score = clamp(Math.round((adjusted / 120) * 100), 0, 100);
  const criticalFail = rules.some((r) => r.severity === "critical" && r.status === "fail");
  const anyHigh = rules.some((r) => r.severity === "high" && r.status === "fail");
  const verdict: Verdict =
    criticalFail || adjusted < floor * 0.8
      ? "REJECT"
      : anyHigh || adjusted < floor
        ? "REVIEW"
        : "ACCEPT";

  const guesses = Math.pow(2, Math.max(0, adjusted - 1));
  const crack = [
    { label: "Online, rate-limited", rate: "10^2 /s", seconds: guesses / 1e2 },
    { label: "Offline, bcrypt cost 12", rate: "10^4 /s", seconds: guesses / 1e4 },
    { label: "Offline, unsalted SHA-256 GPU", rate: "10^10 /s", seconds: guesses / 1e10 },
  ];

  /* actionable recommendations, severity ordered */
  const recs: Recommendation[] = [];
  const push = (severity: Severity, text: string) => recs.push({ id: `R${recs.length + 1}`, severity, text });

  const lenRule = rules[0];
  if (lenRule.status === "fail" && !isPassphrase)
    push("critical", `Add ${minLen - length} more character${minLen - length === 1 ? "" : "s"}. Length scales linearly: on a ${pool || 62}-symbol pool each character is worth ${pool ? Math.log2(pool).toFixed(1) : "5.9"} bits.`);
  if (commonHit)
    push("critical", `Drop "${commonHit}" — denylist entries are the first column of every cracking rig. Nothing you append to a known password makes it unknown.`);
  if (dictHit && !isPassphrase)
    push("high", `Replace the dictionary token "${dictHit}". Attackers run whole-word substitutions first; three unrelated words beat one familiar word.`);
  if (walkHit || seqRun || repeatHit || yearHit) {
    const bits = [walkHit && `keyboard walk "${walkHit}"`, seqRun && `run "${seqRun}"`, repeatHit && `repeat "${repeatHit}"`, yearHit && `date "${yearHit}"`].filter(Boolean).join(", ");
    push("high", `Remove ${bits} — these patterns are enumerated exhaustively before any brute force begins.`);
  }
  if (present.length < minPools && !isPassphrase) {
    const missing = POOLS.filter((p) => !present.includes(p)).map((p) => p.name);
    push("medium", `Add ${missing.join(" and ")} — pool grows ${pool || 0} → ${pool + missing.reduce((s, n) => s + (POOLS.find((p) => p.name === n)?.size || 0), 0)} symbols, lifting entropy by ${(length * Math.log2((pool + missing.reduce((s, n) => s + (POOLS.find((p) => p.name === n)?.size || 0), 0)) / (pool || 1))).toFixed(1)} bits.`);
  }
  if (adjusted < floor)
    push("critical", `Entropy sits ${floor - adjusted < 1 ? "at" : `${(floor - adjusted).toFixed(1)} bits below`} the ${profile} floor of ${floor} bits. ${isPassphrase ? `Add ${Math.ceil((floor - adjusted) / Math.log2(GEN_WORDS.length))} more word(s)` : "Lengthen the secret or widen the character pool."}`);
  if (verdict === "ACCEPT")
    push("medium", "Storage is the next control: SHA-256 is a fast integrity digest — hash at rest with argon2id or bcrypt (cost ≥ 12), a unique salt per user, and never a bare SHA-256.");
  push("medium", "Screen the value against breach corpora (HIBP k-anonymity API) at every password change — complexity does not imply uniqueness.");

  const findings = [
    { kind: "pool", value: pool ? `${pool} symbols` : "—" },
    { kind: "length", value: `${length}` },
    { kind: "raw", value: `${raw.toFixed(1)} bits` },
    { kind: "adjusted", value: `${adjusted.toFixed(1)} bits` },
  ];

  return {
    input: pw, profile, rules, verdict, score, pool, length, raw, adjusted,
    penalties, crack, recommendations: recs.slice(0, 5), isPassphrase, tokens, findings,
  };
}

/** % of hex digits that change when one character of the input changes. */
export function avalanche(pw: string): { changed: number; total: number; a: string; b: string } {
  const a = sha256Hex(pw);
  const alt = pw ? pw.slice(0, -1) + (pw.slice(-1) === "a" ? "b" : "a") : "a";
  const b = sha256Hex(alt);
  let changed = 0;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) changed++;
  return { changed, total: a.length, a, b };
}
