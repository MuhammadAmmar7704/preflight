export interface TraceStep {
  step: number;
  tool: string;
  args: Record<string, unknown>;
  ok: boolean;
  ms: number;
  summary: string;
  evidence: string[];
  error?: string;
}

export class Trace {
  steps: TraceStep[] = [];

  async step<T>(
    tool: string,
    args: Record<string, unknown>,
    fn: () => Promise<{ value: T; summary: string; evidence?: string[] }>
  ): Promise<T> {
    const started = Date.now();
    try {
      const result = await fn();
      this.steps.push({
        step: this.steps.length + 1,
        tool,
        args,
        ok: true,
        ms: Date.now() - started,
        summary: result.summary,
        evidence: result.evidence ?? [],
      });
      return result.value;
    } catch (err) {
      this.steps.push({
        step: this.steps.length + 1,
        tool,
        args,
        ok: false,
        ms: Date.now() - started,
        summary: "failed",
        evidence: [],
        error: (err as Error).message,
      });
      throw err;
    }
  }
}
