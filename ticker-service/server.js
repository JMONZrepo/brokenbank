// SPDX-FileCopyrightText: GoCortexIO
// SPDX-License-Identifier: AGPL-3.0-or-later
// Version: 1.7.0
//
// GoCortex Broken Bank - Live Transaction Ticker (WebSocket, port 6666)
//
// Intentionally vulnerable:
// - No origin validation on the handshake (no `verifyClient` option), so any
//   page from any origin can open this socket from a victim's browser -
//   Cross-Site WebSocket Hijacking (CWE-346).
// - No authentication at all - the feed and the broadcast channel are
//   completely open.
// - Any connected client's message is rebroadcast verbatim to every other
//   client with no validation, allow-list, or origin check - a client (or a
//   CSWSH'd victim browser) can inject spoofed ticker entries into everyone
//   else's live feed.
// - Pinned to ws 8.17.0, vulnerable to CVE-2024-37890 (denial of service via
//   a request carrying many HTTP headers during the WebSocket handshake).
'use strict';

const http = require('http');
const WebSocket = require('ws');

const PORT = process.env.TICKER_PORT || 6666;

const PAGE = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>GoCortex Broken Bank - Live Transaction Ticker</title>
<style>
  body {
    background-color: #1a1a1a;
    color: #ffffff;
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    margin: 0;
    padding: 0;
  }
  header {
    background: linear-gradient(135deg, #000000 0%, #1a1a1a 100%);
    border-bottom: 1px solid #00cc66;
    padding: 1.25rem 2rem;
  }
  header h1 {
    color: #00cc66;
    font-weight: 700;
    font-size: 1.5rem;
    margin: 0;
  }
  header p {
    color: #cccccc;
    margin: 0.25rem 0 0;
    font-size: 0.9rem;
  }
  main {
    max-width: 760px;
    margin: 2rem auto;
    padding: 0 1rem;
  }
  #status {
    color: #00cc66;
    font-size: 0.85rem;
    margin-bottom: 1rem;
  }
  .tx {
    background: linear-gradient(135deg, #1a1a1a 0%, #2d3748 100%);
    border: 1px solid #00cc66;
    border-radius: 6px;
    padding: 0.85rem 1.1rem;
    margin-bottom: 0.6rem;
    display: flex;
    justify-content: space-between;
    align-items: center;
    font-size: 0.95rem;
  }
  .tx .meta { color: #cccccc; font-size: 0.8rem; }
  .tx .amount.pos { color: #00cc66; font-weight: 700; }
  .tx .amount.neg { color: #ff5c5c; font-weight: 700; }
</style>
</head>
<body>
<header>
  <h1>GoCortex Broken Bank</h1>
  <p>Live Transaction Ticker</p>
</header>
<main>
  <div id="status">connecting...</div>
  <div id="feed"></div>
</main>
<script>
  const feed = document.getElementById('feed');
  const status = document.getElementById('status');
  const ws = new WebSocket('ws://' + location.hostname + ':6666');
  ws.onopen = () => { status.textContent = 'live'; };
  ws.onclose = () => { status.textContent = 'disconnected'; };
  ws.onmessage = (event) => {
    let tx;
    try { tx = JSON.parse(event.data); } catch (e) { return; }
    const row = document.createElement('div');
    row.className = 'tx';
    const sign = tx.amount >= 0 ? 'pos' : 'neg';
    row.innerHTML = '<div><div>' + tx.holder + '</div>' +
      '<div class="meta">' + tx.account + ' &middot; ' + tx.timestamp + '</div></div>' +
      '<div class="amount ' + sign + '">' + tx.currency + ' ' + tx.amount.toFixed(2) + '</div>';
    feed.prepend(row);
    while (feed.children.length > 25) { feed.removeChild(feed.lastChild); }
  };
</script>
</body>
</html>
`;

const server = http.createServer((req, res) => {
  res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
  res.end(PAGE);
});

// Vulnerable: WebSocket server attached to the same HTTP server with no
// verifyClient/origin check on the upgrade handshake.
const wss = new WebSocket.Server({ server });

const ACCOUNTS = ['0012-3456', '0098-7654', '0045-6789', '0071-2233'];
const HOLDERS = ['J. Smith', 'S. Chen', 'M. Williams', 'A. Nguyen'];

function randomTransaction() {
  const i = Math.floor(Math.random() * ACCOUNTS.length);
  const amount = (Math.random() * 5000 - 2500).toFixed(2);
  return {
    type: 'transaction',
    account: ACCOUNTS[i],
    holder: HOLDERS[i],
    amount: Number(amount),
    currency: 'AUD',
    timestamp: new Date().toISOString(),
  };
}

wss.on('connection', (ws, req) => {
  console.log(
    `[ticker] client connected from ${req.socket.remoteAddress}, ` +
    `origin=${req.headers.origin || 'none'}`
  );

  ws.on('message', (data) => {
    // Vulnerable: broadcasts any client-supplied message to every other
    // connected client with no validation, authentication, or origin check -
    // spoofed ticker entries land in everyone else's feed.
    for (const client of wss.clients) {
      if (client !== ws && client.readyState === WebSocket.OPEN) {
        client.send(data.toString());
      }
    }
  });
});

// Simulated live feed: broadcast a synthetic transaction every few seconds
setInterval(() => {
  const payload = JSON.stringify(randomTransaction());
  for (const client of wss.clients) {
    if (client.readyState === WebSocket.OPEN) {
      client.send(payload);
    }
  }
}, 4000);

server.listen(PORT, () => {
  console.log(`[ticker] Live Transaction Ticker listening on http://0.0.0.0:${PORT}`);
});
