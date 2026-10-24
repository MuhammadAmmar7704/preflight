import type { Evidence } from "./types.js";

export class Ledger {
  private items: Evidence[] = [];

  add(entry: Omit<Evidence, "id">): Evidence {
    const duplicate = this.items.find(
      (item) =>
        item.source === entry.source &&
        item.claim === entry.claim &&
        item.message === entry.message &&
        item.file === entry.file &&
        item.line === entry.line
    );
    if (duplicate) return duplicate;

    const item: Evidence = { id: `ev_${this.items.length + 1}`, ...entry };
    this.items.push(item);
    return item;
  }

  all(): Evidence[] {
    return [...this.items];
  }

  get(id: string): Evidence | undefined {
    return this.items.find((e) => e.id === id);
  }

  hasClaim(claim: string): boolean {
    return this.items.some((e) => e.claim === claim);
  }
}
