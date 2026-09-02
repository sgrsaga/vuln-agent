const test = require("node:test");
const assert = require("node:assert/strict");
const http = require("node:http");
const { isPalindrome, handleRequest } = require("../index.js");

test("isPalindrome recognizes simple palindromes", () => {
  assert.equal(isPalindrome("racecar"), true);
  assert.equal(isPalindrome("hello"), false);
});

test("isPalindrome ignores case and punctuation", () => {
  assert.equal(isPalindrome("A man, a plan, a canal: Panama"), true);
});

test("GET /health returns 200 and status ok", async () => {
  const server = http.createServer(handleRequest);
  await new Promise((resolve) => server.listen(0, resolve));
  const { port } = server.address();

  const response = await new Promise((resolve, reject) => {
    http.get(`http://127.0.0.1:${port}/health`, (res) => {
      let data = "";
      res.on("data", (chunk) => (data += chunk));
      res.on("end", () => resolve({ status: res.statusCode, data }));
    }).on("error", reject);
  });

  assert.equal(response.status, 200);
  assert.deepEqual(JSON.parse(response.data), { status: "ok" });
  server.close();
});
