const http = require("node:http");

function isPalindrome(s) {
  const normalized = s.toLowerCase().replace(/[^a-z0-9]/g, "");
  return normalized === [...normalized].reverse().join("");
}

function handleRequest(req, res) {
  if (req.url === "/health") {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ status: "ok" }));
    return;
  }
  res.writeHead(404, { "Content-Type": "application/json" });
  res.end(JSON.stringify({ error: "not found" }));
}

if (require.main === module) {
  const server = http.createServer(handleRequest);
  server.listen(8080, () => console.log("listening on :8080"));
}

module.exports = { isPalindrome, handleRequest };
