import type { SecurityEvent } from '../types.js';

type EventHandler = (event: SecurityEvent) => void;

type EventMap = {
  violation: EventHandler;
  block: EventHandler;
  allow: EventHandler;
  alert: EventHandler;
  '*': EventHandler;
};

/**
 * Lightweight typed event bus for security observability.
 * Zero dependencies — no EventEmitter import required.
 */
class GuardrailEvents {
  private listeners = Object.create(null) as Record<keyof EventMap, Set<EventHandler>>;

  constructor() {
    this.listeners.violation = new Set();
    this.listeners.block = new Set();
    this.listeners.allow = new Set();
    this.listeners.alert = new Set();
    this.listeners['*'] = new Set();
  }

  on<K extends keyof EventMap>(event: K, handler: EventMap[K]): () => void {
    this.listeners[event].add(handler);
    return () => this.off(event, handler);
  }

  off<K extends keyof EventMap>(event: K, handler: EventMap[K]): void {
    this.listeners[event].delete(handler);
  }

  emit(event: SecurityEvent): void {
    const type = event.type as keyof EventMap;
    for (const handler of this.listeners[type] ?? []) {
      try {
        handler(event);
      } catch {
        // Never let observer failures break the security path
      }
    }
    for (const handler of this.listeners['*']) {
      try {
        handler(event);
      } catch {
        // swallow
      }
    }
  }

  /** Structured JSON audit log helper */
  audit(event: SecurityEvent): string {
    return JSON.stringify({
      source: 'guardrail',
      ...event,
    });
  }

  removeAllListeners(): void {
    for (const key of Object.keys(this.listeners) as (keyof EventMap)[]) {
      this.listeners[key].clear();
    }
  }
}

export const events = new GuardrailEvents();
