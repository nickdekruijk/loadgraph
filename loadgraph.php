<?php
// loadgraph.php — single-file load average viewer

define('MAX_POINTS', 1500);

$logfile = file_exists('./load.log') ? './load.log' : '/var/log/load.log';

$ranges = [
    'hour'  => 3600,
    'day'   => 86400,
    'week'  => 604800,
    'month' => 2592000,
    'year'  => 31536000,
    'all'   => 0,
];

function parseLogLine(string $line): ?array {
    $p = preg_split('/\s+/', trim($line));
    // 4-column: timestamp load1 load5 load15
    if (count($p) >= 4 && is_numeric($p[0]) && strlen($p[0]) >= 9) {
        return [(int)$p[0], (float)$p[1], (float)$p[2], (float)$p[3]];
    }
    // 5-column: linenum timestamp load1 load5 load15
    if (count($p) >= 5 && is_numeric($p[1]) && strlen($p[1]) >= 9) {
        return [(int)$p[1], (float)$p[2], (float)$p[3], (float)$p[4]];
    }
    return null;
}

// Binary search: returns the byte offset just before the line with cutoff timestamp
function findStartOffset($fh, int $cutoff): int {
    fseek($fh, 0, SEEK_END);
    $high = ftell($fh);
    $low  = 0;

    while ($high - $low > 512) {
        $mid = (int)(($low + $high) / 2);
        fseek($fh, $mid);
        fgets($fh); // skip to start of next complete line
        $line = fgets($fh);
        if ($line === false) { $high = $mid; continue; }
        $row = parseLogLine($line);
        if ($row === null) { $low = $mid + 1; continue; }

        if ($row[0] < $cutoff) {
            $low = ftell($fh); // advance past this line
        } else {
            $high = $mid;
        }
    }

    return max(0, $low - 512); // small buffer so we never miss the first matching line
}

function readLog(string $file, int $cutoff): array {
    $fh = fopen($file, 'rb');
    if (!$fh) return [];

    if ($cutoff > 0) {
        $startPos = findStartOffset($fh, $cutoff);
        fseek($fh, $startPos);
        if ($startPos > 0) fgets($fh); // discard potential partial line at seek offset
    }

    // Estimate decimation step from remaining bytes
    $posStart = ftell($fh);
    fseek($fh, 0, SEEK_END);
    $remaining = ftell($fh) - $posStart;
    fseek($fh, $posStart);

    $estLines = max(1, (int)($remaining / 30)); // ~30 bytes per log line
    $step     = max(1, (int)ceil($estLines / MAX_POINTS));

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
        $labels[] = $ts * 1000; // milliseconds for Chart.js time axis
        $load1[]  = $l1;
        $load5[]  = $l5;
        $load15[] = $l15;
    }

    echo json_encode(compact('labels', 'load1', 'load5', 'load15'));
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
    html, body { height: 100%; overflow: hidden; background: #0f1117; color: #e0e0e0; font-family: system-ui, -apple-system, sans-serif; }
    body { display: flex; flex-direction: column; }

    header {
      flex-shrink: 0;
      display: flex; align-items: center; gap: 10px; flex-wrap: wrap;
      padding: 10px 16px;
      background: #1a1d2b;
      border-bottom: 1px solid #2d2f3e;
    }
    h1 { font-size: 1rem; font-weight: 600; white-space: nowrap; }

    .presets { display: flex; gap: 5px; flex-wrap: wrap; }
    .presets button {
      padding: 4px 11px; font-size: 0.82rem;
      border: 1px solid #3a3d52; border-radius: 4px;
      background: transparent; color: #9ca3af; cursor: pointer;
      transition: background .12s, color .12s, border-color .12s;
    }
    .presets button:hover  { background: #2d2f3e; color: #e0e0e0; }
    .presets button.active { background: #3b5bdb; border-color: #3b5bdb; color: #fff; font-weight: 500; }

    #info { margin-left: auto; font-size: 0.75rem; color: #6b7280; white-space: nowrap; }

    .chart-wrap { flex: 1; position: relative; padding: 12px 16px; min-height: 0; }
    canvas { display: block; width: 100% !important; height: 100% !important; }

    #error {
      position: absolute; top: 50%; left: 50%; transform: translate(-50%,-50%);
      background: #1a1d2b; border: 1px solid #f87171; border-radius: 6px;
      padding: 14px 20px; color: #f87171; font-size: 0.88rem; display: none; white-space: pre;
    }
    #loader {
      position: absolute; inset: 0; display: none;
      align-items: center; justify-content: center;
      background: rgba(15,17,23,.55); color: #6b7280; font-size: 0.85rem;
    }
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
  <div id="loader">Laden…</div>
  <div id="error"></div>
</div>

<script src="https://cdn.jsdelivr.net/npm/luxon@3/build/global/luxon.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4/dist/chart.umd.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/chartjs-adapter-luxon@1/dist/chartjs-adapter-luxon.umd.min.js"></script>
<script>
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
    plugins: {
      legend: {
        labels: { color: '#9ca3af', boxWidth: 12, padding: 16, font: { size: 12 } }
      },
      tooltip: {
        backgroundColor: '#1a1d2b',
        borderColor: '#3a3d52',
        borderWidth: 1,
        titleColor: '#e0e0e0',
        bodyColor: '#9ca3af',
        callbacks: {
          title: items => luxon.DateTime.fromMillis(items[0].parsed.x).toFormat('dd-MM-yyyy HH:mm:ss'),
          label: ctx  => ` ${ctx.dataset.label}: ${ctx.parsed.y.toFixed(2)}`
        }
      }
    },
    scales: {
      x: {
        type: 'time',
        ticks: { color: '#6b7280', maxRotation: 0, autoSkip: true, maxTicksLimit: 8 },
        grid:  { color: 'rgba(255,255,255,.04)' },
        border: { color: '#2d2f3e' }
      },
      y: {
        beginAtZero: true,
        ticks: { color: '#6b7280' },
        grid:  { color: 'rgba(255,255,255,.04)' },
        border: { color: '#2d2f3e' },
        title: { display: true, text: 'Load Average', color: '#6b7280', font: { size: 11 } }
      }
    }
  }
});

async function loadData(range) {
  const loader = document.getElementById('loader');
  const errEl  = document.getElementById('error');

  loader.style.display = 'flex';
  errEl.style.display  = 'none';

  try {
    const res  = await fetch(`?data=1&range=${range}`);
    const data = await res.json();

    if (data.error) {
      errEl.textContent   = data.error;
      errEl.style.display = 'block';
      return;
    }

    chart.data.labels           = data.labels;
    chart.data.datasets[0].data = data.load1;
    chart.data.datasets[1].data = data.load5;
    chart.data.datasets[2].data = data.load15;
    chart.update('none');

    document.getElementById('info').textContent =
      data.labels.length.toLocaleString('nl') + ' punten';
  } catch (e) {
    errEl.textContent   = 'Verbindingsfout: ' + e.message;
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

loadData('day');
</script>
</body>
</html>
