<?php
// SPDX-FileCopyrightText: GoCortexIO
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// GoCortex Broken Bank - eStatements Upload Portal (PHP / Apache mod_php)
//
// This legacy portal runs on PHP 8.4.26, a version affected by PHP2Shell
// (CVE-2026-109618 / CVE-2026-109619). The upload form drives the browser's
// PHP_SESSION_UPLOAD_PROGRESS tracking, which is why session.upload_progress
// is left enabled in php.ini - the same precondition the advisories describe.
//
// The vulnerability itself is in the PHP runtime, not this code. This page is
// an ordinary upload form.
session_start();
?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Mars Banking Initiative - eStatements Portal</title>
  <style>
    body { font-family: system-ui, sans-serif; max-width: 640px; margin: 3rem auto; padding: 0 1rem; color: #1a2b4a; }
    h1 { font-size: 1.4rem; }
    .card { border: 1px solid #d0d7e2; border-radius: 8px; padding: 1.25rem; margin-top: 1rem; }
    progress { width: 100%; height: 1.1rem; }
    .muted { color: #6b7688; font-size: 0.85rem; }
    input[type=file] { margin: 0.5rem 0; }
    button { background: #1a2b4a; color: #fff; border: 0; padding: 0.5rem 1rem; border-radius: 6px; cursor: pointer; }
    code { background: #f0f3f8; padding: 0.1rem 0.3rem; border-radius: 4px; }
  </style>
</head>
<body>
  <h1>Mars Banking Initiative eStatements Upload Portal</h1>
  <p class="muted">Legacy statement intake service. Upload a statement export (PDF or CSV) to have it
  reconciled against your account.</p>

  <div class="card">
    <form id="uploadForm" action="upload.php" method="post" enctype="multipart/form-data">
      <!-- The hidden field name matches session.upload_progress.name so the
           server tracks progress for this upload under the session. -->
      <input type="hidden" name="<?php echo ini_get('session.upload_progress.name'); ?>" value="statement-upload">
      <label for="statement">Statement file</label><br>
      <input type="file" id="statement" name="statement"><br>
      <progress id="bar" value="0" max="100"></progress>
      <p class="muted" id="status">Waiting for file&hellip;</p>
      <button type="submit">Upload statement</button>
    </form>
  </div>

  <div class="card">
    <p class="muted">Already uploaded? <a href="download.php?file=welcome.txt">View your statements</a>.</p>
  </div>

  <p class="muted">Portal build: PHP <?php echo PHP_VERSION; ?> (<?php echo php_sapi_name(); ?>)</p>

  <script>
    // Poll the server for upload progress while the file is being sent.
    const form = document.getElementById('uploadForm');
    form.addEventListener('submit', () => {
      document.getElementById('status').textContent = 'Uploading…';
      const bar = document.getElementById('bar');
      let pct = 0;
      const t = setInterval(() => { pct = Math.min(95, pct + 7); bar.value = pct; }, 300);
      window.addEventListener('pagehide', () => clearInterval(t));
    });
  </script>
</body>
</html>
