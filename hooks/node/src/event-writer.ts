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
//
// That last sentence is why the drain writes synchronously off the timer rather
// than through a write stream. A stream write reports its failure later, on an
// event, by which time the batch has already been spliced out of the buffer and
// there is nothing left to attribute the loss to; Node's own documentation says
// the per-write callback "may or may not" be called with the error, so the count
// cannot be recovered there either. A container whose disk filled up would then
// record five thousand events, write none of them, and report zero dropped. The
// synchronous write is off the application's call path, it costs one blocking
// append per flush interval, and it makes the outcome of every write knowable at
// the moment it happens, which is the only way a loss can be counted at all.

import { randomBytes } from "node:crypto";
import { appendFileSync, mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { countDropped, countWritten, noteFailure, snapshot } from "./hook-status";
import type { EgressEvent } from "./egress-event";

export interface EventSink {
  record(event: EgressEvent): void;
  /** Best effort flush, called when the process is on its way out. */
  close(): void;
}

const FLUSH_INTERVAL_MS = 200;

/** Stage the sink reports failures under, matching the Python hook's spelling. */
const STAGE_FLUSH = "writer.flush";

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

  /**
   * Write what is buffered, and count it either way.
   *
   * The batch stays in the buffer across the write. Nothing is removed until its
   * fate is known, so a failed write counts exactly the events it lost instead
   * of losing them off the end of a splice. Nothing else runs between the write
   * and the removal: the append is synchronous, so the buffer cannot grow under
   * it.
   */
  #flush(): void {
    const count = this.#pending.length;
    if (count === 0) return;
    try {
      appendFileSync(this.#eventPath, `${this.#pending.join("\n")}\n`);
      countWritten(count);
    } catch {
      countDropped(count);
      noteFailure(STAGE_FLUSH);
    }
    this.#pending.length = 0;
    // The accounting is rewritten with every batch and not only on the way out.
    // A process killed by a container stop or an OOM handler never reaches
    // close(), and without this it leaves a stream of events beside a window
    // nobody measured, which suppresses every claim those events were collected
    // to support. What the sidecar then holds is the window as of the last
    // flush: a lower bound, which can only understate the run.
    this.#writeStatus();
  }

  /**
   * Drain on the way out.
   *
   * At exit there is no call path left to slow down, and the alternative is
   * losing every event that was still in the buffer when the process ended.
   */
  close(): void {
    if (this.#closed) return;
    this.#closed = true;
    if (this.#timer !== undefined) {
      clearTimeout(this.#timer);
      this.#timer = undefined;
    }
    this.#flush();
    this.#writeStatus();
  }

  /**
   * The hook's own account of itself, kept out of the event stream.
   *
   * Spec section 5 wants a disabled hook to be visible rather than indistinct
   * from a quiet one, ADR-009 wants dropped events counted, and a dormancy
   * claim needs to know how long this process was watched. None of the three
   * fits in the event schema, which is a closed set of properties and carries
   * no clock, so all of them land here, where `periskop-runtime-collector`
   * reads them back. Contract: schemas/hook-status.schema.json.
   *
   * Written rather than appended: a second line would make the file two JSON
   * documents, and the reader would take neither.
   */
  #writeStatus(): void {
    try {
      writeFileSync(this.#statusPath, `${JSON.stringify(snapshot())}\n`);
    } catch {
      // The one loss that cannot be reported anywhere, since this is the thing
      // that does the reporting.
    }
  }
}
