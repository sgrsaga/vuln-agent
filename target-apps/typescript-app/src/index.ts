import http from "node:http";

export function wordCount(text: string): number {
  const trimmed = text.trim();
  return trimmed === "" ? 0 : trimmed.split(/\s+/).length;
}

export function handleRequest(
  req: http.IncomingMessage,
  res: http.ServerResponse
): void {
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
