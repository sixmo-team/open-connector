import type { TransitFileStore } from "../../core/types.ts";

import { expect, it, vi } from "vitest";
import { gmailActionHandlers } from "./executors.ts";
import { gmailMaxAttachmentBytes } from "./limits.ts";

function transitFile(stream: ReadableStream<Uint8Array>): File {
  const file = new File([], "attachment.bin", { type: "application/octet-stream" });
  Object.defineProperty(file, "stream", { value: () => stream });
  return file;
}

function context(files: File[], signal?: AbortSignal) {
  const fetcher = vi.fn<typeof fetch>(async () => Response.json({ id: "sent", threadId: "thread" }));
  const transitFiles: TransitFileStore = {
    maxBytes: gmailMaxAttachmentBytes * 2,
    read: async (id) => {
      const file = files[Number(id)]!;
      return { file, name: file.name, mimeType: file.type, sizeBytes: file.size };
    },
    create: async () => {
      throw new Error("Sending must not create transit files");
    },
    delete: async () => {
      throw new Error("Sending must not delete transit files");
    },
  };
  return { userId: "me", accessToken: "token", fetcher, transitFiles, signal };
}

it("cancels an attachment body before Gmail can send or create a draft", async () => {
  for (const handler of [gmailActionHandlers.send_email, gmailActionHandlers.create_draft]) {
    const abort = new AbortController();
    const reason = new Error("Owner processing cancelled");
    let pulls = 0;
    const stream = new ReadableStream<Uint8Array>({
      pull(controller) {
        if (pulls++ === 0) {
          controller.enqueue(new Uint8Array([1]));
          queueMicrotask(() => abort.abort(reason));
        } else controller.close();
      },
    });
    const owner = context([transitFile(stream)], abort.signal);
    await expect(
      handler({ to: "reader@example.com", body: "hello", attachments: [{ file: { fileId: "0" } }] }, owner),
    ).rejects.toBe(reason);
    expect(owner.fetcher).not.toHaveBeenCalled();
  }
});

it.each([1, 2])("limits actual combined attachment bytes, not reported sizes (%i files)", async (count) => {
  const size = Math.floor(gmailMaxAttachmentBytes / count) + 1;
  const files = Array.from({ length: count }, () =>
    transitFile(
      new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(new Uint8Array(size));
          controller.close();
        },
      }),
    ),
  );
  const owner = context(files);
  await expect(
    gmailActionHandlers.send_email(
      {
        to: "reader@example.com",
        body: "hello",
        attachments: files.map((_, index) => ({ file: { fileId: String(index) } })),
      },
      owner,
    ),
  ).rejects.toMatchObject({ status: 413 });
  expect(owner.fetcher).not.toHaveBeenCalled();
});
