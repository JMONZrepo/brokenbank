<?php
// SPDX-FileCopyrightText: GoCortexIO
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// GoCortex Broken Bank - eStatements Upload Portal: upload handler
//
// INTENTIONALLY VULNERABLE: Unrestricted file upload (CWE-434).
//
// The uploaded file is written into a directory under the web root with its
// attacker-supplied name and no check of extension, MIME type or content. A
// file called shell.php therefore lands at /uploads/shell.php and is executed
// by mod_php on the next request. This is the realistic persistence step an
// attacker takes after any RCE on this host, including PHP2Shell, and it is
// what SAST and DAST tooling flags on this endpoint.
session_start();

$uploadDir = __DIR__ . '/uploads/';
if (!is_dir($uploadDir)) {
    mkdir($uploadDir, 0777, true);
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST' || !isset($_FILES['statement'])) {
    header('Location: index.php');
    exit;
}

$name = $_FILES['statement']['name'];                 // attacker-controlled
$tmp  = $_FILES['statement']['tmp_name'];

// No validation of extension, MIME type or magic bytes - the whole point.
$dest = $uploadDir . basename($name);

header('Content-Type: text/plain');
if (move_uploaded_file($tmp, $dest)) {
    echo "Statement received: " . basename($name) . "\n";
    echo "Stored at: /uploads/" . basename($name) . "\n";
    echo "It will be reconciled against your account shortly.\n";
} else {
    http_response_code(500);
    echo "Upload failed.\n";
}
