<?php
// search.php (REMEDIATED)
require_once 'db_config.php'; // now exposes $pdo, not $conn (mysqli)

$keyword = $_GET['keyword'] ?? '';

// FIX 1 (Flaw A - SQLi): PDO prepared statement.
// Query plan is compiled BEFORE $keyword exists in the pipeline,
// so injected SQL syntax can never alter the execution plan.
$stmt = $pdo->prepare(
    "SELECT id, name, illness_history FROM patient_records WHERE name LIKE :kw"
);
$stmt->execute([':kw' => '%' . $keyword . '%']);
$rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

// FIX 2 (Flaw B/C - Reflected XSS): context-aware output encoding
// applied at the exact point data crosses into the HTML rendering plane.
$safeKeyword = htmlspecialchars($keyword, ENT_QUOTES, 'UTF-8');

if (count($rows) > 0) {
    foreach ($rows as $row) {
        $safeName    = htmlspecialchars($row['name'], ENT_QUOTES, 'UTF-8');
        $safeHistory = htmlspecialchars($row['illness_history'], ENT_QUOTES, 'UTF-8');
        echo "<div>Result found for keyword: {$safeKeyword}<br>";
        echo "Patient: {$safeName} | History: {$safeHistory}</div><hr>";
    }
} else {
    // The "no results" branch is just as reachable by attacker input —
    // it needs identical encoding, not just the success branch.
    echo "No records found for: {$safeKeyword}";
}
