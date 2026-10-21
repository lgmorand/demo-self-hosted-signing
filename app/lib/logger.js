'use strict';

/**
 * Structured logger: every entry is written to stdout (journald on the VM) as one JSON line
 * and kept in a bounded in-memory ring buffer so it can be served by GET /logs.
 *
 * Never log secrets: no private key, no token, no attestation token. Only identifiers and outcomes.
 */
class Logger {
  constructor({ capacity = 1000, sink = (line) => console.log(line), now = () => new Date() } = {}) {
    this.capacity = capacity;
    this.sink = sink;
    this.now = now;
    this.buffer = [];
    this.seq = 0;
  }

  log(event, fields = {}) {
    const entry = { seq: ++this.seq, time: this.now().toISOString(), event, ...fields };
    this.buffer.push(entry);
    if (this.buffer.length > this.capacity) this.buffer.shift();
    this.sink(JSON.stringify(entry));
    return entry;
  }

  /** Most recent entries, oldest first. `after` returns only entries newer than that sequence number. */
  entries({ limit = 100, event, after = 0 } = {}) {
    let result = this.buffer.filter((entry) => entry.seq > after);
    if (event) {
      const wanted = new Set(event.split(','));
      result = result.filter((entry) => wanted.has(entry.event));
    }
    return result.slice(-Math.max(1, Math.min(limit, this.capacity)));
  }
}

module.exports = { Logger };
