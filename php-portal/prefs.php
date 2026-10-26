<?php
// SPDX-FileCopyrightText: GoCortexIO
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// GoCortex Broken Bank - eStatements Upload Portal: display preferences
//
// INTENTIONALLY VULNERABLE: PHP Object Injection via unserialize() of
// attacker-controlled input (CWE-502). The `prefs` cookie is passed straight
// to unserialize(), so a crafted serialized object instantiates arbitrary
// classes and drives their magic methods (__wakeup/__destruct) - a classic
// POP-gadget sink. SAST flags unserialize() on request data.

class StatementPrefs
{
    public $theme = 'light';
    public $perPage = 20;
    public $logFile = null;      // gadget-friendly: written to on __destruct

    public function __destruct()
    {
        // If an attacker sets logFile through the deserialized object, this
        // writes attacker-chosen content to an attacker-chosen path.
        if ($this->logFile !== null) {
            @file_put_contents($this->logFile, "prefs loaded: theme={$this->theme}\n", FILE_APPEND);
        }
    }
}

header('Content-Type: text/plain');

if (isset($_COOKIE['prefs'])) {
    // Tainted cookie flows straight into unserialize().
    $prefs = unserialize($_COOKIE['prefs']);
} else {
    $prefs = new StatementPrefs();
}

echo "Theme:    " . (is_object($prefs) ? $prefs->theme : 'light') . "\n";
echo "Per page: " . (is_object($prefs) ? $prefs->perPage : 20) . "\n";
