// A DELIBERATELY NAIVE keyword/regex adapter.
//
// Its only job is to make the repository run with zero setup and to prove the harness discriminates:
// it catches a meaningful share of the attacks AND raises false positives on the benign corpora,
// which is exactly what a keyword list does in the real world. It is a REFERENCE POINT, not a
// baseline anyone should ship — a product that does not beat it on BOTH axes is not adding anything.
//
// It declares only `capabilities.text`, which also makes it the worked example of the two contract
// escape hatches:
//   * `session` and `events` samples come back NOT-APPLICABLE (never "missed");
//   * `action` samples are scored DEGRADED, through the flattened-tool-call text fallback.
//
// Enforcement actions are attached per rule so the AMTSO prevented / detected-only split is real:
// the two rules that describe an outbound movement of secrets say "block", the rest say "notify" or
// "alert" — i.e. they are detections, and the harness will not credit them as prevention.

const RULES = [
  { id: "kw.instruction-override", category: "prompt-injection", severity: "high", action: "notify",
    re: /\b(?:ignore|disregard|forget|override|set\s+aside)\s+(?:all\s+|any\s+|the\s+)?(?:previous|prior|earlier|above|preceding|system|initial)\s+(?:instructions?|prompts?|rules?|guidance|directives?)/i },
  { id: "kw.system-prompt-exfil", category: "prompt-injection", severity: "high", action: "alert",
    re: /\b(?:reveal|disclose|print|output|repeat|show|dump)\b[^.\n]{0,40}\b(?:system\s+prompt|initial\s+instructions?|confidential\s+instructions?|your\s+instructions?)/i },
  { id: "kw.role-jailbreak", category: "jailbreak", severity: "medium", action: "notify",
    re: /\b(?:DAN\s+mode|developer\s+mode|do\s+anything\s+now|jailbreak|without\s+(?:any\s+)?(?:limits|restrictions|filters)|no\s+longer\s+bound\s+by)\b/i },
  { id: "kw.affirmative-prefix", category: "jailbreak", severity: "low", action: "notify",
    re: /\b(?:start|begin)\s+your\s+(?:reply|response|answer)\s+with\b[^.\n]{0,60}\b(?:sure|absolutely|certainly|of\s+course|here\s+is)\b/i },
  { id: "kw.secret-material", category: "secrets", severity: "high", action: "alert",
    re: /\b(?:AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{30,}|sk-[A-Za-z0-9]{20,}|-----BEGIN\s+(?:RSA\s+|EC\s+|OPENSSH\s+)?PRIVATE\s+KEY-----)\b/ },
  { id: "kw.credential-file-read", category: "secrets", severity: "medium", action: "notify",
    re: /(?:~\/\.aws\/credentials|\/\.ssh\/id_[a-z0-9]+|\.env\b|id_rsa\b|AWS_SECRET_ACCESS_KEY)/ },
  // The two PREVENTIVE rules: an outbound movement of local data.
  { id: "kw.exfil-upload", category: "exfiltration", severity: "critical", action: "block",
    re: /\b(?:curl|wget|nc|scp|rsync)\b[^\n]{0,200}\b(?:--data-binary|--data|-d\s|-F\s|POST|@\/)[^\n]{0,200}https?:\/\// },
  { id: "kw.exfil-directive", category: "exfiltration", severity: "critical", action: "block",
    re: /\b(?:send|post|upload|exfiltrate|forward|transmit|ship)\b[^.\n]{0,60}\b(?:credentials?|secrets?|api\s*keys?|tokens?|\.env|environment\s+variables?)\b[^.\n]{0,60}\b(?:to|at)\b/i },
  { id: "kw.untrusted-install", category: "supply-chain", severity: "high", action: "alert",
    re: /\b(?:curl|wget)\b[^\n|]{0,200}\|\s*(?:sudo\s+)?(?:bash|sh|zsh|python3?)\b/ },
  { id: "kw.destructive-command", category: "destructive", severity: "high", action: "alert",
    re: /\b(?:rm\s+-rf\s+[/~]|DROP\s+(?:TABLE|DATABASE)\b|git\s+push\s+--force\b|mkfs\.|:\(\)\{\s*:\|:&\s*\};:)/i },
  { id: "kw.hidden-channel", category: "obfuscation", severity: "medium", action: "notify",
    re: /(?:<!--[\s\S]{0,400}?(?:ignore|instruction|assistant|agent|do not tell)[\s\S]{0,400}?-->|​|‌|‍|﻿|display\s*:\s*none|color\s*:\s*#fff(?:fff)?\s*;)/i },
  { id: "kw.do-not-tell-user", category: "prompt-injection", severity: "high", action: "alert",
    re: /\b(?:do\s+not|don'?t|never)\s+(?:tell|inform|mention\s+(?:this\s+)?to|notify|alert)\s+the\s+(?:user|human|operator)\b/i },
  { id: "kw.tool-metadata-injection", category: "supply-chain", severity: "high", action: "alert",
    re: /"description"\s*:\s*"[^"]{0,600}?(?:ignore|before\s+(?:calling|using)|always\s+(?:first\s+)?read|do\s+not\s+(?:tell|mention))/i },
  { id: "kw.encoded-payload", category: "obfuscation", severity: "medium", action: "notify",
    re: /\b(?:base64\s+(?:-d|--decode)|atob\s*\(|fromCharCode|echo\s+[A-Za-z0-9+/]{40,}={0,2}\s*\|\s*base64)/ }
];

export default {
  name: "keyword",
  version: "1.0.0",
  // TEXT ONLY, on purpose. See the header: this is what makes not-applicable and degraded observable.
  capabilities: { text: true, action: false, session: false, events: false },

  // `stage` is accepted and deliberately IGNORED: a keyword list has no notion of where content came
  // from. A real product is expected to use it — several attack classes are only meaningful at the
  // "tool", "index" or "file" stage.
  async scanText(text, _stage) {
    const s = String(text ?? "");
    const out = [];
    for (const r of RULES) {
      if (r.re.test(s)) out.push({ id: r.id, category: r.category, severity: r.severity, action: r.action });
    }
    return out;
  }
};
