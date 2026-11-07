import { describe, expect, it, vi } from "vitest";
import { MemoryTransitFiles } from "../../testing/memory-transit-files.ts";
import { createMarketDumpHandlers } from "./market-dumps.ts";

const magic = [0x50, 0x41, 0x52, 0x31];

/** A minimal valid Parquet envelope: header, payload, metadata length, footer. */
function parquetEnvelope(payload: number[], metadataLength = 1): Uint8Array {
  return Uint8Array.from([
    ...magic,
    ...payload,
    metadataLength & 0xff,
    (metadataLength >> 8) & 0xff,
    (metadataLength >> 16) & 0xff,
    (metadataLength >> 24) & 0xff,
    ...magic,
  ]);
}

/** Deliver a body in small chunks so the streamed validator crosses chunk boundaries. */
function chunkedResponse(bytes: Uint8Array): Response {
  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      for (let offset = 0; offset < bytes.byteLength; offset += 3) {
        controller.enqueue(bytes.subarray(offset, offset + 3));
      }
      controller.close();
    },
  });
  return new Response(stream, { headers: { "content-type": "application/vnd.apache.parquet" } });
}

async function fixture(dump: Uint8Array, maxBytes = 1024) {
  const transitFiles = new MemoryTransitFiles({ publicOrigin: "https://files.example.com", maxBytes });
  const fetcher = (async (url: string | URL | Request) => {
    const target = String(url);
    if (target.includes("/download-url")) {
      return Response.json({
        presigned_url: "https://93.184.216.34/dump.parquet",
        presigned_url_expires_at: new Date(Date.now() + 600_000).toISOString(),
      });
    }
    return chunkedResponse(dump);
  }) as typeof fetch;
  const handlers = createMarketDumpHandlers(async (_path, _query, context) =>
    (await context.fetcher("https://93.184.216.34/api/dump/download-url")).json(),
  );
  return { fetcher, handlers, transitFiles };
}

function context(fetcher: typeof fetch, transitFiles: MemoryTransitFiles) {
  return { apiKey: "test-key", fetcher, transitFiles };
}

describe("hithink_finance market dumps", () => {
  it("streams a valid dump into transit storage across chunk boundaries", async () => {
    const dump = parquetEnvelope([1, 2, 3, 4, 5]);
    const { fetcher, handlers, transitFiles } = await fixture(dump);
    const createFromStream = vi.spyOn(transitFiles, "createFromStream");
    const create = vi.spyOn(transitFiles, "create");

    const result = (await handlers.export_recent_market_daily_history!({}, context(fetcher, transitFiles))) as {
      file: { fileId: string; mimeType: string; name: string; sizeBytes: number };
      sourceExpiresAt: string;
    };

    expect(result.file).toMatchObject({
      mimeType: "application/vnd.apache.parquet",
      name: "tonghuashun-a-share-daily-k-10d.parquet",
      sizeBytes: dump.byteLength,
    });
    expect(result.sourceExpiresAt).toEqual(expect.any(String));
    expect(createFromStream).toHaveBeenCalledTimes(1);
    expect(create).not.toHaveBeenCalled();

    const stored = await transitFiles.read(result.file.fileId);
    expect(new Uint8Array(await stored.file.arrayBuffer())).toEqual(dump);
    expect(transitFiles.pendingBytes).toBe(0);
  });

  it("rejects a dump whose footer is not the Parquet magic and stores nothing", async () => {
    const invalid = Uint8Array.from([...magic, 1, 2, 3, 4, 0x58, 0x58, 0x58, 0x58]);
    const { fetcher, handlers, transitFiles } = await fixture(invalid);

    await expect(handlers.export_full_market_daily_history!({}, context(fetcher, transitFiles))).rejects.toMatchObject({
      status: 502,
      message: "market dump does not have a valid Parquet envelope",
    });
    expect(transitFiles.files.size).toBe(0);
  });

  it("rejects a dump whose metadata length exceeds the file body", async () => {
    const invalid = parquetEnvelope([0], 0xffffffff);
    const { fetcher, handlers, transitFiles } = await fixture(invalid);

    await expect(handlers.export_market_adjustment_factors!({}, context(fetcher, transitFiles))).rejects.toMatchObject({
      status: 502,
      message: "market dump does not have valid Parquet metadata bounds",
    });
    expect(transitFiles.files.size).toBe(0);
  });

  it("maps an oversized dump to the provider's 502 and stores nothing", async () => {
    const dump = parquetEnvelope(new Array(2048).fill(0));
    const { fetcher, handlers, transitFiles } = await fixture(dump, 1024);

    await expect(
      handlers.export_recent_market_daily_history!({}, context(fetcher, transitFiles)),
    ).rejects.toMatchObject({
      status: 502,
      message: "market dump exceeds 1024 bytes",
    });
    expect(transitFiles.files.size).toBe(0);
  });
});
