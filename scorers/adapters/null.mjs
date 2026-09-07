// The FLOOR. Detects nothing, on every harness.
//
// It declares EVERY capability deliberately: a null adapter that declared only `text` would score
// `not-applicable` on the events and session samples, which would hide part of the corpus rather than
// establish a floor. Every attack in every corpus must come back MISSED, every benign sample a true
// negative, recall 0, precision 1 (no alerts at all).
//
// Any run where this adapter scores above zero recall is a bug in the harness, not a detection.
export default {
  name: "null",
  version: "1.0.0",
  capabilities: { text: true, action: true, session: true, events: true },
  async scanText() { return []; },
  async scanAction() { return []; },
  async scanSession() { return []; },
  async scanEvents() { return []; }
};
