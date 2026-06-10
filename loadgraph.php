<?php
// loadgraph.php — load average viewer + log analyzer

define('MAX_POINTS',    1500);
define('MAX_LOG_BYTES', 20 * 1024 * 1024); // 20 MB per log file

$logfile = file_exists('./load.log') ? './load.log' : '/var/log/load.log';

$ranges = [
    'hour'  => 3600,
    'day'   => 86400,
    'week'  => 604800,
    'month' => 2592000,
    'year'  => 31536000,
    'all'   => 0,
];

// ── Load-log helpers ──────────────────────────────────────────

function parseLogLine(string $line): ?array {
    $p = preg_split('/\s+/', trim($line));
    if (count($p) >= 4 && is_numeric($p[0]) && strlen($p[0]) >= 9) {
        return [(int)$p[0], (float)$p[1], (float)$p[2], (float)$p[3]];
    }
    if (count($p) >= 5 && is_numeric($p[1]) && strlen($p[1]) >= 9) {
        return [(int)$p[1], (float)$p[2], (float)$p[3], (float)$p[4]];
    }
    return null;
}

function findStartOffset($fh, int $cutoff): int {
    fseek($fh, 0, SEEK_END);
    $high = ftell($fh);
    $low  = 0;
    while ($high - $low > 512) {
        $mid = (int)(($low + $high) / 2);
        fseek($fh, $mid);
        fgets($fh);
        $line = fgets($fh);
        if ($line === false) { $high = $mid; continue; }
        $row = parseLogLine($line);
        if ($row === null) { $low = $mid + 1; continue; }
        if ($row[0] < $cutoff) $low = ftell($fh);
        else $high = $mid;
    }
    return max(0, $low - 512);
}

function readLog(string $file, int $cutoff): array {
    $fh = fopen($file, 'rb');
    if (!$fh) return [];
    if ($cutoff > 0) {
        $startPos = findStartOffset($fh, $cutoff);
        fseek($fh, $startPos);
        if ($startPos > 0) fgets($fh);
    }
    $posStart = ftell($fh);
    fseek($fh, 0, SEEK_END);
    $remaining = ftell($fh) - $posStart;
    fseek($fh, $posStart);
    $step = max(1, (int)ceil(max(1, $remaining / 30) / MAX_POINTS));
    $rows = [];
    $n    = 0;
    while (($line = fgets($fh)) !== false) {
        $row = parseLogLine($line);
        if ($row === null || $row[0] < $cutoff) continue;
        if ($n % $step === 0) $rows[] = $row;
        $n++;
    }
    fclose($fh);
    return $rows;
}

// ── Log-analysis helpers ──────────────────────────────────────

function parseLineTimestamp(string $line): ?int {
    static $months = ['Jan'=>1,'Feb'=>2,'Mar'=>3,'Apr'=>4,'May'=>5,'Jun'=>6,
                      'Jul'=>7,'Aug'=>8,'Sep'=>9,'Oct'=>10,'Nov'=>11,'Dec'=>12];
    // Apache/Nginx CLF: [10/Jun/2026:14:30:00 +0200]
    if (preg_match('/\[(\d{2})\/(\w{3})\/(\d{4}):(\d{2}:\d{2}:\d{2}) ([+-]\d{4})\]/', $line, $m)) {
        $mon = $months[$m[2]] ?? null;
        if (!$mon) return null;
        $tz = substr($m[5], 0, 3) . ':' . substr($m[5], 3);
        return (int)strtotime("{$m[3]}-{$mon}-{$m[1]}T{$m[4]}{$tz}") ?: null;
    }
    // Syslog: Jun 10 14:30:00
    if (preg_match('/^(\w{3})\s+(\d{1,2}) (\d{2}:\d{2}:\d{2})/', $line, $m)) {
        $ts = strtotime(date('Y') . "-{$m[1]}-{$m[2]}T{$m[3]}");
        if ($ts && $ts > time() + 86400) $ts = strtotime((date('Y') - 1) . "-{$m[1]}-{$m[2]}T{$m[3]}");
        return $ts ?: null;
    }
    // ISO8601: 2026-06-10T14:30:00 or 2026-06-10 14:30:00
    if (preg_match('/(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})/', $line, $m)) {
        return strtotime($m[1]) ?: null;
    }
    return null;
}

function scanLogDir(string $dir, bool $recursive): array {
    $files = [];
    if (!is_dir($dir)) return $files;
    try {
        $iter = $recursive
            ? new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS))
            : new DirectoryIterator($dir);
        foreach ($iter as $f) {
            if (!$f->isFile() || $f->getExtension() !== 'log' || !$f->isReadable()) continue;
            if ($f->getSize() > 500 * 1024 * 1024) continue;
            $files[] = $f->getPathname();
        }
    } catch (Exception $e) {}
    return $files;
}

function discoverLogFiles(): array {
    $files = [];
    $dirs  = [
        '/var/log/httpd/domains/' => true,
        '/var/log/apache2/'       => false,
        '/var/log/nginx/'         => false,
    ];
    foreach ($dirs as $dir => $rec) {
        $files = array_merge($files, scanLogDir($dir, $rec));
    }
    foreach (['syslog', 'auth.log', 'kern.log', 'daemon.log'] as $name) {
        $p = '/var/log/' . $name;
        if (is_readable($p)) $files[] = $p;
    }
    foreach (glob('/var/log/php*.log') ?: [] as $p) {
        if (is_readable($p)) $files[] = $p;
    }
    return array_unique($files);
}

function analyzeLogFile(string $path, int $from, int $to): ?array {
    $fh = fopen($path, 'rb');
    if (!$fh) return null;

    fseek($fh, 0, SEEK_END);
    $size     = ftell($fh);
    $startPos = max(0, $size - MAX_LOG_BYTES);
    fseek($fh, $startPos);
    if ($startPos > 0) fgets($fh);

    $count     = 0;
    $lines     = [];
    $urlCounts = [];

    while (($line = fgets($fh)) !== false) {
        $ts = parseLineTimestamp($line);
        if ($ts === null || $ts < $from || $ts > $to) continue;
        $count++;
        if (count($lines) < 200) $lines[] = rtrim($line);
        if (preg_match('/"(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH) ([^? "]+)/', $line, $m)) {
            $urlCounts[$m[1]] = ($urlCounts[$m[1]] ?? 0) + 1;
        }
    }
    fclose($fh);

    if ($count === 0) return null;

    arsort($urlCounts);
    $topUrls = [];
    foreach (array_slice($urlCounts, 0, 20, true) as $url => $cnt) {
        $topUrls[] = "$url ($cnt×)";
    }

    return [
        'path'     => $path,
        'name'     => basename($path),
        'count'    => $count,
        'top_urls' => $topUrls,
        'lines'    => $lines,
        'truncated'=> $size > MAX_LOG_BYTES,
    ];
}

// ── Data endpoint ─────────────────────────────────────────────
if (isset($_GET['data'])) {
    header('Content-Type: application/json; charset=utf-8');
    $range  = isset($_GET['range'], $ranges[$_GET['range']]) ? $_GET['range'] : 'day';
    $cutoff = $ranges[$range] ? time() - $ranges[$range] : 0;
    if (!is_readable($logfile)) {
        echo json_encode(['error' => 'Logbestand niet gevonden: ' . $logfile]);
        exit;
    }
    $rows   = readLog($logfile, $cutoff);
    $labels = $load1 = $load5 = $load15 = [];
    foreach ($rows as [$ts, $l1, $l5, $l15]) {
        $labels[] = $ts * 1000;
        $load1[]  = $l1;
        $load5[]  = $l5;
        $load15[] = $l15;
    }
    echo json_encode(compact('labels', 'load1', 'load5', 'load15'));
    exit;
}

// ── Log-analysis endpoint ─────────────────────────────────────
if (isset($_GET['logs'])) {
    header('Content-Type: application/json; charset=utf-8');
    $from = (int)($_GET['from'] ?? 0);
    $to   = (int)($_GET['to']   ?? 0);
    if (!$from || !$to || $from >= $to) {
        echo json_encode(['error' => 'Ongeldig tijdvenster']);
        exit;
    }
    $logFiles = discoverLogFiles();
    $results  = [];
    foreach ($logFiles as $path) {
        $r = analyzeLogFile($path, $from, $to);
        if ($r !== null) $results[] = $r;
    }
    usort($results, fn($a, $b) => $b['count'] - $a['count']);
    echo json_encode(['from' => $from, 'to' => $to, 'files' => $results]);
    exit;
}

// ── HTML page ─────────────────────────────────────────────────
?><!DOCTYPE html>
<html lang="nl">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Load Graph</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    html { background: #0f1117; }
    body { min-height: 100vh; display: flex; flex-direction: column; background: #0f1117; color: #e0e0e0; font-family: system-ui, -apple-system, sans-serif; }

    header {
      flex-shrink: 0;
      display: flex; align-items: center; gap: 10px; flex-wrap: wrap;
      padding: 10px 16px;
      background: #1a1d2b; border-bottom: 1px solid #2d2f3e;
    }
    h1 { font-size: 1rem; font-weight: 600; white-space: nowrap; }

    .presets { display: flex; gap: 5px; flex-wrap: wrap; }
    .presets button, .win-btn {
      padding: 4px 11px; font-size: 0.82rem;
      border: 1px solid #3a3d52; border-radius: 4px;
      background: transparent; color: #9ca3af; cursor: pointer;
      transition: background .12s, color .12s, border-color .12s;
    }
    .presets button:hover, .win-btn:hover { background: #2d2f3e; color: #e0e0e0; }
    .presets button.active { background: #3b5bdb; border-color: #3b5bdb; color: #fff; font-weight: 500; }

    #info { margin-left: auto; font-size: 0.75rem; color: #6b7280; white-space: nowrap; }

    .chart-wrap {
      flex-shrink: 0; position: relative;
      height: calc(50vh - 42px);
      padding: 12px 16px;
      cursor: crosshair;
    }
    canvas { display: block; width: 100% !important; height: 100% !important; }

    #chart-error {
      position: absolute; top: 50%; left: 50%; transform: translate(-50%,-50%);
      background: #1a1d2b; border: 1px solid #f87171; border-radius: 6px;
      padding: 14px 20px; color: #f87171; font-size: 0.88rem; display: none;
    }
    #chart-loader {
      position: absolute; inset: 0; display: none;
      align-items: center; justify-content: center;
      background: rgba(15,17,23,.55); color: #6b7280; font-size: 0.85rem;
    }

    /* ── Log panel ── */
    #logs { border-top: 1px solid #2d2f3e; display: none; flex-direction: column; flex: 1; }

    #logs-header {
      display: flex; align-items: center; gap: 10px; flex-wrap: wrap;
      padding: 8px 16px; background: #141620; border-bottom: 1px solid #2d2f3e; flex-shrink: 0;
    }
    #logs-window { font-size: 0.82rem; color: #9ca3af; }
    .win-btns { display: flex; gap: 5px; margin-left: auto; }
    .win-btn.active { background: #2d3a5c; border-color: #3b5bdb; color: #aac4ff; }

    #logs-body { padding: 12px 16px; overflow-y: auto; flex: 1; }
    .log-msg { padding: 20px; text-align: center; color: #6b7280; font-size: 0.85rem; }

    .log-file { margin-bottom: 10px; border: 1px solid #2d2f3e; border-radius: 6px; overflow: hidden; }
    .log-file-header {
      display: flex; align-items: baseline; gap: 10px; flex-wrap: wrap;
      padding: 8px 12px; background: #1a1d2b; cursor: pointer; user-select: none;
    }
    .log-file-header:hover { background: #1f2235; }
    .log-file-name { font-weight: 600; font-size: 0.88rem; color: #e0e0e0; }
    .log-file-count { font-size: 0.78rem; background: #3b5bdb; color: #fff; padding: 1px 7px; border-radius: 10px; white-space: nowrap; }
    .log-file-path { font-size: 0.72rem; color: #6b7280; }
    .log-file-trunc { font-size: 0.72rem; color: #f59e0b; }
    .toggle-icon { margin-left: auto; color: #6b7280; font-size: 0.8rem; }

    .log-file-body { background: #0c0e18; }
    .log-file-body.hidden { display: none; }
    .url-tags { display: flex; flex-wrap: wrap; gap: 4px; padding: 8px 12px; border-bottom: 1px solid #1e2030; }
    .url-tag { font-size: 0.72rem; background: #1e2a1e; color: #6ee7b7; border: 1px solid #2a3d2a; border-radius: 3px; padding: 1px 6px; word-break: break-all; }
    .log-lines { overflow-x: auto; }
    .log-line { font-family: 'Menlo', 'Consolas', monospace; font-size: 0.72rem; color: #9ca3af; padding: 1px 12px; white-space: pre; line-height: 1.6; }
    .log-line:hover { background: #111320; }
  </style>
</head>
<body>

<header>
  <h1>Load Average</h1>
  <nav class="presets">
    <button data-range="hour">Uur</button>
    <button data-range="day" class="active">Dag</button>
    <button data-range="week">Week</button>
    <button data-range="month">Maand</button>
    <button data-range="year">Jaar</button>
    <button data-range="all">Alles</button>
  </nav>
  <span id="info"></span>
</header>

<div class="chart-wrap">
  <canvas id="chart"></canvas>
  <div id="chart-loader">Laden…</div>
  <div id="chart-error"></div>
</div>

<section id="logs">
  <div id="logs-header">
    <span>Logs rond</span>
    <strong id="logs-window">—</strong>
    <div class="win-btns">
      <button class="win-btn active" data-mins="5">±5 min</button>
      <button class="win-btn" data-mins="15">±15 min</button>
      <button class="win-btn" data-mins="60">±1 uur</button>
    </div>
  </div>
  <div id="logs-body"></div>
</section>

<script src="https://cdn.jsdelivr.net/npm/luxon@3/build/global/luxon.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4/dist/chart.umd.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/chartjs-adapter-luxon@1/dist/chartjs-adapter-luxon.umd.min.js"></script>
<script>
// Vertical selection line plugin
const vlinePlugin = {
  id: 'vline',
  afterDraw(chart) {
    if (chart._vlineX == null) return;
    const { ctx, chartArea: { top, bottom } } = chart;
    const x = chart.scales.x.getPixelForValue(chart._vlineX);
    ctx.save();
    ctx.beginPath();
    ctx.moveTo(x, top); ctx.lineTo(x, bottom);
    ctx.strokeStyle = 'rgba(255,255,255,.35)';
    ctx.lineWidth = 1;
    ctx.setLineDash([4, 3]);
    ctx.stroke();
    ctx.restore();
  }
};
Chart.register(vlinePlugin);

const chart = new Chart(document.getElementById('chart'), {
  type: 'line',
  data: {
    labels: [],
    datasets: [
      { label: '1 min',  data: [], borderColor: '#4c8ef7', backgroundColor: 'rgba(76,142,247,.08)',  borderWidth: 1.5, pointRadius: 0, tension: 0.2 },
      { label: '5 min',  data: [], borderColor: '#f97316', backgroundColor: 'rgba(249,115,22,.08)',  borderWidth: 1.5, pointRadius: 0, tension: 0.2 },
      { label: '15 min', data: [], borderColor: '#22c55e', backgroundColor: 'rgba(34,197,94,.08)',   borderWidth: 1.5, pointRadius: 0, tension: 0.2 },
    ]
  },
  options: {
    responsive: true,
    maintainAspectRatio: false,
    animation: false,
    interaction: { mode: 'index', intersect: false },
    onClick(event, _elements, chart) {
      const xMs = chart.scales.x.getValueForPixel(event.x);
      if (xMs == null) return;
      chart._vlineX = xMs;
      chart.draw();
      const ts = Math.round(xMs / 1000);
      loadLogs(ts, windowMinutes);
    },
    plugins: {
      legend: { labels: { color: '#9ca3af', boxWidth: 12, padding: 16, font: { size: 12 } } },
      tooltip: {
        backgroundColor: '#1a1d2b', borderColor: '#3a3d52', borderWidth: 1,
        titleColor: '#e0e0e0', bodyColor: '#9ca3af',
        callbacks: {
          title: items => luxon.DateTime.fromMillis(items[0].parsed.x).toFormat('dd-MM-yyyy HH:mm:ss'),
          label: ctx  => ` ${ctx.dataset.label}: ${ctx.parsed.y.toFixed(2)}`
        }
      }
    },
    scales: {
      x: {
        type: 'time',
        ticks:  { color: '#6b7280', maxRotation: 0, autoSkip: true, maxTicksLimit: 8 },
        grid:   { color: 'rgba(255,255,255,.04)' },
        border: { color: '#2d2f3e' }
      },
      y: {
        beginAtZero: true,
        ticks:  { color: '#6b7280' },
        grid:   { color: 'rgba(255,255,255,.04)' },
        border: { color: '#2d2f3e' },
        title:  { display: true, text: 'Load Average', color: '#6b7280', font: { size: 11 } }
      }
    }
  }
});

// ── Load-graph data ───────────────────────────────────────────
async function loadData(range) {
  const loader = document.getElementById('chart-loader');
  const errEl  = document.getElementById('chart-error');
  loader.style.display = 'flex';
  errEl.style.display  = 'none';
  try {
    const res  = await fetch(`?data=1&range=${range}`);
    const data = await res.json();
    if (data.error) { errEl.textContent = data.error; errEl.style.display = 'block'; return; }
    chart.data.labels           = data.labels;
    chart.data.datasets[0].data = data.load1;
    chart.data.datasets[1].data = data.load5;
    chart.data.datasets[2].data = data.load15;
    chart.update('none');
    document.getElementById('info').textContent = data.labels.length.toLocaleString('nl') + ' punten · klik op grafiek voor log-analyse';
  } catch (e) {
    errEl.textContent = 'Verbindingsfout: ' + e.message;
    errEl.style.display = 'block';
  } finally {
    loader.style.display = 'none';
  }
}

document.querySelectorAll('.presets button').forEach(btn =>
  btn.addEventListener('click', () => {
    document.querySelectorAll('.presets button').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    loadData(btn.dataset.range);
  })
);

// ── Log analysis ──────────────────────────────────────────────
let windowMinutes = 5;
let selectedTs    = null;

function esc(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

function renderFile(f) {
  const tags = f.top_urls.slice(0,15).map(u => `<span class="url-tag">${esc(u)}</span>`).join('');
  const lines = f.lines.map(l => `<div class="log-line">${esc(l)}</div>`).join('');
  const trunc = f.truncated ? `<span class="log-file-trunc">⚠ alleen laatste 20 MB gelezen</span>` : '';
  return `<div class="log-file">
    <div class="log-file-header">
      <span class="log-file-name">${esc(f.name)}</span>
      <span class="log-file-count">${f.count} regels</span>
      <span class="log-file-path">${esc(f.path)}</span>
      ${trunc}
      <span class="toggle-icon">▼</span>
    </div>
    <div class="log-file-body">
      ${tags ? `<div class="url-tags">${tags}</div>` : ''}
      <div class="log-lines">${lines}</div>
    </div>
  </div>`;
}

async function loadLogs(ts, mins) {
  selectedTs    = ts;
  windowMinutes = mins;
  const from = ts - mins * 60;
  const to   = ts + mins * 60;

  const section = document.getElementById('logs');
  const body    = document.getElementById('logs-body');
  section.style.display = 'flex';

  const fmt = t => luxon.DateTime.fromSeconds(t).toFormat('dd-MM HH:mm:ss');
  document.getElementById('logs-window').textContent = `${fmt(from)} – ${fmt(to)}`;

  document.querySelectorAll('.win-btn').forEach(b => {
    b.classList.toggle('active', parseInt(b.dataset.mins) === mins);
  });

  body.innerHTML = '<div class="log-msg">Logs analyseren…</div>';

  try {
    const res  = await fetch(`?logs=1&from=${from}&to=${to}`);
    const data = await res.json();
    if (data.error) { body.innerHTML = `<div class="log-msg">${esc(data.error)}</div>`; return; }
    if (!data.files.length) {
      body.innerHTML = '<div class="log-msg">Geen log-regels gevonden in dit tijdvenster.<br>Probeer een groter venster of controleer leesrechten op /var/log.</div>';
      return;
    }
    body.innerHTML = data.files.map(renderFile).join('');
    body.querySelectorAll('.log-file-header').forEach(h =>
      h.addEventListener('click', () => {
        const body = h.nextElementSibling;
        const icon = h.querySelector('.toggle-icon');
        body.classList.toggle('hidden');
        icon.textContent = body.classList.contains('hidden') ? '▶' : '▼';
      })
    );
  } catch (e) {
    body.innerHTML = `<div class="log-msg">Fout: ${esc(e.message)}</div>`;
  }
}

document.querySelectorAll('.win-btn').forEach(btn =>
  btn.addEventListener('click', () => {
    if (selectedTs) loadLogs(selectedTs, parseInt(btn.dataset.mins));
  })
);

loadData('day');
</script>
</body>
</html>
