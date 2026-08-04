// Getting events out of the process without getting in its way.
//
// ADR-009 forbids synchronous I/O on the call path and gives the reason: the
// per-call budget is a millisecond, and a disk write is not something that fits
// inside one predictably. So recording an event appends to a bounded array and
// returns. A timer that does not hold the process open drains it later.
//
// The buffer is bounded rather than growable because the memory belongs to the
// application, not to us. When it overflows the oldest event goes, and the count
// of what went is reported through the status file. Dropping is acceptable;
// dropping quietly is not.

import { randomBytes } from "node:crypto";
import { appendFileSync, createWriteStream, mkdirSync, type WriteStream } from "node:fs";
import { join } from "node:path";

import { countDropped, countRecorded, snapshot } from "./hook-status";
import type { EgressEvent } from "./egress-event";

export interface EventSink {
  record(event: EgressEvent): void;
  /** Best effort flush, called when the process is on its way out. */
  close(): void;
}

const FLUSH_INTERVAL_MS = 200;

/**
 * File this process appends to, unique among every writer in the directory.
 *
 * The extension is what the collector selects on, so anything but .jsonl is a
 * stream it never reads. The pid alone would not make the name unique enough:
 * pids are reused, so a short lived process can land on a finished one's number
 * and append its events to that run's file, merging two runs into one stream
 * nobody can separate again.
 */
export function streamName(pid: number): string {
  return `node-${pid}-${randomBytes(4).toString("hex")}.jsonl`;
}

export class FileEventSink implements EventSink {
  readonly #pending: string[] = [];
  readonly #limit: number;
  readonly #eventPath: string;
  readonly #statusPath: string;
  #stream: WriteStream | undefined;
  #timer: NodeJS.Timeout | undefined;
  #closed = false;

  constructor(outputDir: string, pid: number, maxBufferedEvents: number) {
    this.#limit = maxBufferedEvents;
    const name = streamName(pid);
    this.#eventPath = join(outputDir, name);
    // Ends in .json, not .jsonl, so the collector never reads a run's own
    // accounting back as a malformed event.
    this.#statusPath = join(outputDir, `${name}.status.json`);
    mkdirSync(outputDir, { recursive: true });
  }

  get eventPath(): string {
    return this.#eventPath;
  }

  get statusPath(): string {
    return this.#statusPath;
  }

  record(event: EgressEvent): void {
    if (this.#closed) return;
    if (this.#pending.length >= this.#limit) {
      this.#pending.shift();
      countDropped();
    }
    this.#pending.push(JSON.stringify(event));
    countRecorded();
    this.#schedule();
  }

  #schedule(): void {
    if (this.#timer !== undefined) return;
    this.#timer = setTimeout(() => {
      this.#timer = undefined;
      this.#flush();
    }, FLUSH_INTERVAL_MS);
    // An observation tool must not be the reason a process stays alive.
    this.#timer.unref();
  }

  #flush(): void {
    if (this.#pending.length === 0) return;
    const batch = this.#pending.splice(0, this.#pending.length).join("\n");
    if (this.#stream === undefined) {
      this.#stream = createWriteStream(this.#eventPath, { flags: "a" });
      // A write error here is the hook's problem and nobody else's.
      this.#stream.on("error", () => undefined);
    }
    this.#stream.write(`${batch}\n`);
  }

  /**
   * Drain on the way out.
   *
   * This is the one synchronous write in the file, and it is deliberate: at exit
   * there is no call path left to slow down, and the alternative is losing every
   * event that was still in the buffer when the process ended.
   */
  close(): void {
    if (this.#closed) return;
    this.#closed = true;
    if (this.#timer !== undefined) {
      clearTimeout(this.#timer);
      this.#timer = undefined;
    }
    try {
      if (this.#pending.length > 0) {
        const batch = this.#pending.splice(0, this.#pending.length).join("\n");
        appendFileSync(this.#eventPath, `${batch}\n`);
      }
      this.#stream?.end();
    } catch {
      // Nothing left to do about it, and nothing worth failing an exit over.
    }
    this.#writeStatus();
  }

  /**
   * The hook's own account of itself, kept out of the event stream.
   *
   * Spec section 5 wants a disabled hook to be visible rather than indistinct
   * from a quiet one, and ADR-009 wants dropped events counted. Neither fits in
   * the event schema, which is a closed set of properties, so both land here.
   */
  #writeStatus(): void {
    try {
      appendFileSync(this.#statusPath, `${JSON.stringify(snapshot())}\n`);
    } catch {
      // The status file is a courtesy to an operator, not a correctness concern.
    }
  }
}
