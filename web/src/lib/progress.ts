/**
 * Transfer progress: bytes done, smoothed rate and ETA. Shared by the
 * uploader and the downloader. Pure (time is injected), unit-tested.
 *
 * @module
 */

/** A progress snapshot, as passed to `onProgress` callbacks. */
export interface Progress {
  /** Plaintext bytes confirmed done (uploaded and acknowledged / decrypted and written). */
  readonly done: number;
  /** Total plaintext bytes. */
  readonly total: number;
  /** Smoothed rate in bytes per second (0 until measurable). */
  readonly rate: number;
  /** Estimated seconds remaining (`Infinity` while unknown). */
  readonly eta: number;
}

/**
 * Exponentially weighted rate meter. The time constant (`tauMs`) trades
 * stability for reactivity; 5 s suits 32 MiB upload parts and 64 KiB
 * download segments alike.
 */
export class RateMeter {
  readonly total: number;
  private readonly tauMs: number;
  private lastT: number;
  private lastDone = 0;
  private rate = 0;
  private started = false;

  constructor(total: number, now: number, tauMs = 5000) {
    this.total = total;
    this.lastT = now;
    this.tauMs = tauMs;
  }

  /** Record that `done` bytes are complete at time `now` (ms) and return a snapshot. */
  update(done: number, now: number): Progress {
    const dt = now - this.lastT;
    const db = done - this.lastDone;
    if (dt > 0 && db >= 0) {
      const inst = (db / dt) * 1000;
      if (!this.started) {
        this.rate = inst;
        this.started = db > 0;
      } else {
        const a = 1 - Math.exp(-dt / this.tauMs);
        this.rate += a * (inst - this.rate);
      }
      this.lastT = now;
      this.lastDone = done;
    } else if (db < 0) {
      // Progress went backwards (should not happen): resynchronise.
      this.lastDone = done;
      this.lastT = now;
    }
    return this.snapshot(done);
  }

  /** Forget the rate (e.g. after a pause) without losing `done`. */
  reset(done: number, now: number): void {
    this.lastT = now;
    this.lastDone = done;
    this.rate = 0;
    this.started = false;
  }

  snapshot(done: number): Progress {
    const remaining = Math.max(0, this.total - done);
    const eta = remaining === 0 ? 0 : this.rate > 0 ? remaining / this.rate : Infinity;
    return { done, total: this.total, rate: this.rate, eta };
  }
}
