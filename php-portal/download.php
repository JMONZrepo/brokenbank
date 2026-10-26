<?php
// SPDX-FileCopyrightText: GoCortexIO
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// GoCortex Broken Bank - eStatements Upload Portal: statement viewer
//
// INTENTIONALLY VULNERABLE: Local/Remote File Inclusion and path traversal
// (CWE-98 / CWE-22). The `file` parameter is concatenated into an include()
// with no sanitisation, so `?file=../../../../etc/passwd` reads arbitrary
// files and, because allow_url_include is On in php.ini, a `?file=http://...`
// value includes and executes a remote PHP file. SAST flags the tainted
// include() directly.
$statementsDir = __DIR__ . '/statements/';
$file = isset($_GET['file']) ? $_GET['file'] : 'welcome.txt';

header('Content-Type: text/plain');

// Tainted path flows straight into include(). No realpath() containment check.
include $statementsDir . $file;
