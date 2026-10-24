export class GemmaUnavailableError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "GemmaUnavailableError";
  }
}

export interface GemmaTool {
  name: string;
  description: string;
  parameters: Record<string, unknown>;
}

export interface GemmaFunctionCall {
  name: string;
  args: Record<string, unknown>;
}

export interface GemmaResponse {
  text?: string;
  functionCalls: GemmaFunctionCall[];
  raw: unknown;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export class GemmaClient {
  private readonly apiKey: string;
  private readonly model: string;

  constructor(apiKey: string, model?: string) {
    this.apiKey = apiKey;
    this.model = model ?? process.env.GEMMA_MODEL ?? "gemma-4-26b-a4b-it";
  }

  async generate(
    contents: unknown[],
    tools: GemmaTool[],
    system: string
  ): Promise<GemmaResponse> {
    const body = {
      systemInstruction: { parts: [{ text: system }] },
      contents,
      tools: [{ functionDeclarations: tools }],
      toolConfig: {
        functionCallingConfig: { mode: "AUTO" },
      },
      generationConfig: { temperature: 0 },
    };

    let lastError = "Gemma request failed";

    for (let attempt = 0; attempt < 3; attempt++) {
      let res: Response;
      try {
        res = await fetch(
          `https://generativelanguage.googleapis.com/v1beta/models/${this.model}:generateContent`,
          {
            method: "POST",
            headers: {
              "content-type": "application/json",
              "x-goog-api-key": this.apiKey,
            },
            body: JSON.stringify(body),
            signal: AbortSignal.timeout(45_000),
          }
        );
      } catch (err) {
        lastError = (err as Error).message;
        if (attempt < 2) {
          await sleep(1000 * 2 ** attempt);
          continue;
        }
        throw new GemmaUnavailableError(lastError);
      }

      if (res.ok) {
        const data = (await res.json()) as any;
        const parts = data.candidates?.[0]?.content?.parts ?? [];
        const functionCalls: GemmaFunctionCall[] = [];

        for (const part of parts) {
          if (part.functionCall?.name) {
            functionCalls.push({
              name: part.functionCall.name,
              args: part.functionCall.args ?? {},
            });
          }
        }

        const text = parts
          .filter((part: any) => typeof part.text === "string")
          .map((part: any) => part.text)
          .join("\n");

        return { text: text || undefined, functionCalls, raw: data };
      }

      const detail = (await res.text()).slice(0, 300);
      lastError = `Gemma ${res.status}: ${detail}`;

      if (res.status === 429 || res.status >= 500) {
        if (attempt < 2) {
          await sleep(1000 * 2 ** attempt);
          continue;
        }
        throw new GemmaUnavailableError(lastError);
      }

      throw new GemmaUnavailableError(lastError);
    }

    throw new GemmaUnavailableError(lastError);
  }
}
