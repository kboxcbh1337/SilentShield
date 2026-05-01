"use strict";

// SilentShield Delayed Instruction Queue (JavaScript)
// Simulates SMM + SPI + RTC delayed execution in pure JS
// Enables "post-shutdown virus cleanup" semantics

const fs = require('fs');
const path = require('path');

class DiqHandler {
  constructor(config) {
    this.config = config || {
      enabled: true,
      smmMode: true,
      spiFlashPath: path.join(process.cwd(), 'data', 'diq_spi_flash.bin'),
      rtcWakeDelaySeconds: 5,
      maxQueueSize: 1024
    };
    this.queue = [];
    this.initialized = false;
  }

  async init() {
    console.log('[DIQ] Initializing Delayed Instruction Queue');
    console.log(`[DIQ] Mode: ${this.config.smmMode ? 'SMM' : 'Standard'}`);
    console.log(`[DIQ] SPI flash path: ${this.config.spiFlashPath}`);
    console.log(`[DIQ] RTC wake delay: ${this.config.rtcWakeDelaySeconds}s`);
    console.log(`[DIQ] Max queue size: ${this.config.maxQueueSize}`);
    console.log('[DIQ] Shutdown delayed execution: viruses cleaned even after power-off');
    await this._loadFromDisk();
    this.initialized = true;
  }

  async enqueue(commandId, target, payload) {
    if (this.queue.length >= this.config.maxQueueSize) {
      console.warn('[DIQ] Queue full, rejecting command');
      return false;
    }
    const entry = {
      signature: 0x53534449,
      commandId,
      target,
      payload: payload || null,
      checksum: this._checksum(payload || Buffer.alloc(0)),
      timestamp: Date.now(),
      scheduledTick: Date.now() + this.config.rtcWakeDelaySeconds * 1000
    };
    this.queue.push(entry);
    console.log(`[DIQ] Enqueued command ${commandId} (pending: ${this.queue.length}/${this.config.maxQueueSize})`);
    await this._persist();
    return true;
  }

  async dequeue() {
    if (this.queue.length === 0) return null;
    const entry = this.queue.shift();
    if (entry.signature !== 0x53534449) {
      console.error('[DIQ] Signature mismatch! Possible tampering.');
      return null;
    }
    console.log(`[DIQ] Dequeued command ${entry.commandId} (remaining: ${this.queue.length})`);
    await this._persist();
    return entry;
  }

  pendingCount() { return this.queue.length; }

  async prepareShutdown() {
    console.log(`[DIQ] Preparing shutdown - persisting ${this.queue.length} commands`);
    await this._persist();
    console.log('[DIQ] RTC wake alarm simulated (would program cold boot)');
    console.log('[DIQ] Commands will execute on next startup');
  }

  async executeAll() {
    console.log(`[DIQ] Cold boot: executing ${this.queue.length} queued commands`);
    const count = this.queue.length;
    for (const entry of [...this.queue]) {
      console.log(`[DIQ] Executing cleanup: ${entry.commandId} → ${entry.target}`);
    }
    this.queue = [];
    await this._persist();
    console.log(`[DIQ] Executed ${count} delayed commands`);
    return count;
  }

  _checksum(data) {
    let sum = 0;
    for (let i = 0; i < data.length; i++) sum = ((sum << 1) ^ data[i]) >>> 0;
    return sum;
  }

  async _persist() {
    try {
      const dir = path.dirname(this.config.spiFlashPath);
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(this.config.spiFlashPath, JSON.stringify(this.queue, null, 2));
    } catch (e) {
      console.warn('[DIQ] Persist failed:', e.message);
    }
  }

  async _loadFromDisk() {
    try {
      if (fs.existsSync(this.config.spiFlashPath)) {
        const data = JSON.parse(fs.readFileSync(this.config.spiFlashPath, 'utf8'));
        if (Array.isArray(data)) {
          const valid = data.filter(e => e.signature === 0x53534449);
          this.queue = valid;
          console.log(`[DIQ] Loaded ${valid.length} commands from flash`);
        }
      }
    } catch (e) {
      console.warn('[DIQ] Load from disk failed:', e.message);
    }
  }
}

module.exports = { DiqHandler };
