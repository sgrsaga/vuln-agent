import test from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { wordCount, handleRequest } from "../src/index";

test("wordCount counts space-separated words", () => {
  assert.equal(wordCount("hello world"), 2);
  assert.equal(wordCount("  a  b   c "), 3);
});

test("wordCount returns 0 for empty/whitespace-only input", () => {
  assert.equal(wordCount(""), 0);
  assert.equal(wordCount("   "), 0);
});

test("GET /health returns 200 and status ok", async () => {
  const server = http.createServer(handleRequest);
  await new Promise<void>((resolve) => server.listen(0, resolve));
  const address = server.address();
  const port = typeof address === "object" && address ? address.port : 0;

  const response = await new Promise<{ status: number; data: string }>(
    (resolve, reject) => {
      http
        .get(`http://127.0.0.1:${port}/health`, (res) => {
          let data = "";
          res.on("data", (chunk) => (data += chunk));
          res.on("end", () => resolve({ status: res.statusCode ?? 0, data }));
        })
        .on("error", reject);
    }
  );

  assert.equal(response.status, 200);
  assert.deepEqual(JSON.parse(response.data), { status: "ok" });
  server.close();
});
