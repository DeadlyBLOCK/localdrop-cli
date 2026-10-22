<?php
/*
 * localdrop: send files between devices on the same network.
 *
 * One file. GET serves the page, POST is the signalling relay. File contents
 * travel peer to peer over WebRTC; the server only relays the handshake plus
 * the names and sizes shown in the accept prompt.
 *
 * Needs PHP 7.4+ and a writable DATA_DIR. Serve it over HTTPS: copying,
 * sharing and keep-awake only work on secure pages (transfers work either way).
 */

declare(strict_types=1);

/* ------------------------------------------------------------------ config */

// Room state lives here. Outside the web root is best. If it is inside, the
// folder gets a deny-all .htaccess and every file in it is a .php file that
// exits on its first line, so nothing is readable over HTTP either way.
const DATA_DIR = __DIR__ . '/localdrop-data';

// Devices are grouped by public IP. Behind a reverse proxy or CDN, name the
// header carrying the visitor's IP: 'HTTP_CF_CONNECTING_IP' (Cloudflare) or
// 'HTTP_X_FORWARDED_FOR' (one nginx/Caddy hop). Leave it empty when visitors
// connect directly, otherwise anyone can forge it and join other rooms.
const IP_HEADER = '';

// STUN finds a route between devices. Add TURN if some networks never connect.
const ICE_SERVERS = [
    ['urls' => ['stun:stun.l.google.com:19302', 'stun:stun1.l.google.com:19302']],
    // ['urls' => 'turn:turn.example.com:3478', 'username' => 'user', 'credential' => 'secret'],
];

const PEER_TTL  = 10.0;    // seconds without a poll before a device drops off
const AWAY_TTL  = 75.0;    // the same for background tabs, which browsers slow down
const MAX_PEERS = 24;      // devices per room
const MAX_MSG   = 16384;   // bytes per signalling message
const MAX_QUEUE = 131072;  // undelivered bytes held per device
const MAX_BATCH = 32;      // messages per send request
const MAX_BODY  = 262144;  // request body
const RATE_10S  = 2000;    // requests per room per 10 seconds
const GC_AFTER  = 900;     // delete room files idle this many seconds

/* --------------------------------------------------------------------- api */

const KINDS = ['phone', 'tablet', 'computer'];
const OSES  = ['ios', 'android', 'windows', 'macos', 'linux', 'chromeos'];
const GUARD = "<?php exit; ?>\n";
const JF    = JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE;

ini_set('display_errors', '0');

function reply(array $d, int $code = 200): void
{
    http_response_code($code);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');
    header('X-Content-Type-Options: nosniff');
    echo json_encode($d, JF);
    exit;
}

function deny(string $error, int $code = 400): void
{
    reply(['ok' => false, 'error' => $error], $code);
}

function client_ip(): string
{
    if (IP_HEADER !== '' && !empty($_SERVER[IP_HEADER])) {
        $parts = explode(',', (string)$_SERVER[IP_HEADER]);
        $ip = trim((string)end($parts)); // right-most entry is the one our own proxy added
        if (filter_var($ip, FILTER_VALIDATE_IP)) {
            return $ip;
        }
    }
    return (string)($_SERVER['REMOTE_ADDR'] ?? '0.0.0.0');
}

function network_key(string $ip): string
{
    $ip = (string)preg_replace('/^::ffff:/i', '', $ip);
    if ($ip === '::1') {
        $ip = '127.0.0.1';
    }
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        $o = array_map('intval', explode('.', $ip));
        $lan = $o[0] === 10 || $o[0] === 127 || ($o[0] === 172 && $o[1] >= 16 && $o[1] <= 31)
            || ($o[0] === 192 && $o[1] === 168) || ($o[0] === 169 && $o[1] === 254);
        // Server on the LAN: group by /24. Public server: everyone behind one NAT address.
        return $lan ? 'lan|' . $o[0] . '.' . $o[1] . '.' . $o[2] : 'v4|' . $ip;
    }
    $bin = @inet_pton($ip);
    return ($bin !== false && strlen($bin) === 16) ? 'v6|' . bin2hex(substr($bin, 0, 8)) : 'x|' . $ip;
}

function ensure_dir(): void
{
    if (!is_dir(DATA_DIR) && !@mkdir(DATA_DIR, 0750, true) && !is_dir(DATA_DIR)) {
        deny('data folder is not writable', 500);
    }
    if (!is_file(DATA_DIR . '/.htaccess')) {
        @file_put_contents(DATA_DIR . '/.htaccess', "<IfModule mod_authz_core.c>\nRequire all denied\n</IfModule>\n<IfModule !mod_authz_core.c>\nDeny from all\n</IfModule>\n");
        @file_put_contents(DATA_DIR . '/index.html', '');
    }
}

function unguard($s): string
{
    return is_string($s) && strncmp($s, GUARD, strlen(GUARD)) === 0 ? (string)substr($s, strlen(GUARD)) : '';
}

// Random per-install key for hashing room names and device ids. Created on first use.
function server_key(): string
{
    $fh = @fopen(DATA_DIR . '/key.php', 'c+');
    if ($fh === false || !flock($fh, LOCK_EX)) {
        deny('data folder is not writable', 500);
    }
    $key = unguard(stream_get_contents($fh));
    if (!preg_match('/^[a-f0-9]{64}$/', $key)) {
        $key = bin2hex(random_bytes(32));
        rewind($fh);
        ftruncate($fh, 0);
        fwrite($fh, GUARD . $key);
        fflush($fh);
    }
    flock($fh, LOCK_UN);
    fclose($fh);
    return $key;
}

function clean_name($v): string
{
    $v = is_string($v) ? preg_replace(['/\p{C}+/u', '/[\s\p{Z}]+/u'], ['', ' '], $v) : null;
    if (!is_string($v) || !preg_match('/^.{1,32}/u', trim($v), $m) || trim($m[0]) === '') {
        return 'device';
    }
    return trim($m[0]);
}

function valid_signal($d): bool
{
    if (!is_array($d) || !is_string($d['c'] ?? null) || !preg_match('/^[a-f0-9]{16,32}$/', $d['c'])) {
        return false;
    }
    $k = $d['k'] ?? null;
    if ($k === 'offer') {
        return is_string($d['sdp'] ?? null) && is_array($d['m'] ?? null);
    }
    if ($k === 'answer') {
        return is_string($d['sdp'] ?? null);
    }
    if ($k === 'ice') {
        return is_array($d['list'] ?? null) && count($d['list']) <= 32;
    }
    return $k === 'cancel' || $k === 'decline';
}

function read_state($fp): array
{
    $s = json_decode(unguard(stream_get_contents($fp)), true);
    return is_array($s) && is_array($s['p'] ?? null) ? $s : ['p' => []];
}

function write_state($fp, array $s): void
{
    $json = json_encode($s, JF);
    rewind($fp);
    ftruncate($fp, 0);
    fwrite($fp, GUARD . ($json === false ? '{"p":{}}' : $json));
    fflush($fp);
    flock($fp, LOCK_UN);
    fclose($fp);
}

function do_poll(array &$st, string $me, array $in, float $now, int &$http): array
{
    $ack = $in['ack'] ?? 0;
    $ack = is_int($ack) && $ack > 0 && $ack < PHP_INT_MAX - 1000000 ? $ack : 0;
    $p = $st['p'][$me] ?? null;
    if (!is_array($p)) {
        if (count($st['p']) >= MAX_PEERS) {
            $http = 429;
            return ['ok' => false, 'error' => 'room is full'];
        }
        $p = ['q' => [], 'qb' => 0, 'seq' => $ack + 1];
    } else {
        $q = is_array($p['q'] ?? null) ? $p['q'] : [];
        // Messages stay queued until the client confirms them, so a lost
        // response never loses a handshake.
        if ($ack > 0 && $q) {
            $q = array_values(array_filter($q, static fn($m) => (int)($m['q'] ?? 0) > $ack));
        }
        $p['q'] = $q;
        $p['qb'] = (int)array_sum(array_column($q, 'z'));
        // Keep numbering ahead of everything this tab has seen, even if it
        // spent time in another room in between.
        if ((int)($p['seq'] ?? 0) <= $ack) {
            $p['seq'] = $ack + 1;
        }
    }
    $kind = $in['kind'] ?? '';
    $os = $in['os'] ?? '';
    $p['name'] = clean_name($in['name'] ?? null);
    $p['kind'] = in_array($kind, KINDS, true) ? $kind : 'computer';
    $p['os'] = in_array($os, OSES, true) ? $os : '';
    $p['bg'] = ($in['bg'] ?? false) === true;
    $p['seen'] = $now;
    $st['p'][$me] = $p;

    $peers = $msgs = [];
    foreach ($st['p'] as $id => $o) {
        if ($id !== $me) {
            $peers[] = ['id' => $id, 'name' => $o['name'] ?? 'device', 'kind' => $o['kind'] ?? 'computer', 'os' => $o['os'] ?? '', 'bg' => !empty($o['bg'])];
        }
    }
    foreach ($p['q'] as $m) {
        $msgs[] = ['q' => $m['q'], 'f' => $m['f'], 'd' => $m['d']];
    }
    return ['ok' => true, 'peers' => $peers, 'msgs' => $msgs];
}

function do_send(array &$st, string $me, array $in, float $now, int &$http): array
{
    if (!isset($st['p'][$me])) {
        $http = 409;
        return ['ok' => false, 'error' => 'not registered'];
    }
    $st['p'][$me]['seen'] = $now;
    $list = $in['msgs'] ?? null;
    if (!is_array($list) || !$list || count($list) > MAX_BATCH) {
        $http = 400;
        return ['ok' => false, 'error' => 'bad batch'];
    }
    $res = []; // per message: 1 queued, 0 recipient gone, -1 rejected
    foreach ($list as $m) {
        $to = is_array($m) ? ($m['to'] ?? null) : null;
        $d = is_array($m) ? ($m['d'] ?? null) : null;
        if (!is_string($to) || !preg_match('/^p[a-f0-9]{15}$/', $to) || !valid_signal($d)) {
            $res[] = -1;
            continue;
        }
        $t = $st['p'][$to] ?? null;
        if ($to === $me || !is_array($t)) {
            $res[] = 0;
            continue;
        }
        $z = strlen((string)json_encode($d, JF));
        $qb = (int)($t['qb'] ?? 0);
        if ($z > MAX_MSG || $qb + $z > MAX_QUEUE) {
            $res[] = -1;
            continue;
        }
        $seq = (int)($t['seq'] ?? 1);
        $t['q'][] = ['q' => $seq, 'f' => $me, 'd' => $d, 'z' => $z];
        $t['seq'] = $seq + 1;
        $t['qb'] = $qb + $z;
        $st['p'][$to] = $t;
        $res[] = 1;
    }
    return ['ok' => true, 'res' => $res];
}

function api(): void
{
    // Only this page may use the relay; browsers label cross-site requests.
    $site = (string)($_SERVER['HTTP_SEC_FETCH_SITE'] ?? '');
    if ($site !== '' && $site !== 'same-origin') {
        deny('forbidden', 403);
    }
    if ((int)($_SERVER['CONTENT_LENGTH'] ?? 0) > MAX_BODY) {
        deny('request too large', 413);
    }
    $raw = file_get_contents('php://input', false, null, 0, MAX_BODY + 1);
    if (!is_string($raw) || strlen($raw) > MAX_BODY) {
        deny('request too large', 413);
    }
    $in = json_decode($raw, true, 16);
    if (!is_array($in)) {
        deny('invalid json');
    }
    $secret = $in['s'] ?? null;
    if (!is_string($secret) || !preg_match('/^[A-Za-z0-9_-]{32,128}$/', $secret)) {
        deny('bad session');
    }
    $code = $in['room'] ?? '';
    if (!is_string($code) || ($code !== '' && !preg_match('/^[a-z0-9]{6,32}$/', $code))) {
        deny('bad room code');
    }
    $action = is_string($in['a'] ?? null) ? $in['a'] : '';

    ensure_dir();
    $key = server_key();
    // Each tab keeps a random secret. Others only ever see a keyed hash of it,
    // so nobody can poll as another device and read its messages.
    $me = 'p' . substr(hash_hmac('sha256', 'peer|' . $secret, $key), 0, 15);
    $room = $code !== '' ? 'code|' . $code : 'net|' . network_key(client_ip());
    $fp = @fopen(DATA_DIR . '/room-' . substr(hash_hmac('sha256', $room, $key), 0, 24) . '.php', 'c+');
    if ($fp === false || !flock($fp, LOCK_EX)) {
        deny('cannot open room store', 500);
    }

    $st = read_state($fp);
    $now = microtime(true);
    $win = (int)floor($now / 10);
    if (($st['w'] ?? null) !== $win) {
        $st['w'] = $win;
        $st['c'] = 0;
    }
    $st['c'] = (int)($st['c'] ?? 0) + 1;
    if ($st['c'] > RATE_10S) {
        write_state($fp, $st);
        deny('too many requests', 429);
    }
    foreach ($st['p'] as $id => $p) {
        $ttl = is_array($p) && !empty($p['bg']) ? AWAY_TTL : PEER_TTL;
        if (!is_string($id) || !is_array($p) || $now - (float)($p['seen'] ?? 0) > $ttl) {
            unset($st['p'][$id]);
        }
    }

    $http = 200;
    if ($action === 'poll') {
        $out = do_poll($st, $me, $in, $now, $http);
    } elseif ($action === 'send') {
        $out = do_send($st, $me, $in, $now, $http);
    } elseif ($action === 'leave') {
        unset($st['p'][$me]);
        $out = ['ok' => true];
    } else {
        $out = ['ok' => false, 'error' => 'unknown action'];
        $http = 400;
    }
    write_state($fp, $st);

    if (random_int(1, 50) === 1) {
        foreach (glob(DATA_DIR . '/room-*.php') ?: [] as $f) {
            if ((int)@filemtime($f) < time() - GC_AFTER) {
                @unlink($f);
            }
        }
    }
    reply($out, $http);
}

/* ------------------------------------------------------------------ routing */

$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
if ($method === 'POST') {
    api();
}
if ($method !== 'GET' && $method !== 'HEAD') {
    http_response_code(405);
    header('Allow: GET, HEAD, POST');
    exit;
}

$nonce = base64_encode(random_bytes(18));
header('Content-Type: text/html; charset=utf-8');
header("Content-Security-Policy: default-src 'none'; script-src 'nonce-$nonce'; style-src 'nonce-$nonce'; connect-src 'self'; img-src 'self' data: blob:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'");
header('Referrer-Policy: no-referrer');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Permissions-Policy: camera=(), microphone=(), geolocation=()');
header('Cache-Control: no-store');
if ($method === 'HEAD') {
    exit;
}
$cfg = json_encode(['ice' => ICE_SERVERS], JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_UNESCAPED_SLASHES);
?><!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="color-scheme" content="dark light">
<meta name="theme-color" content="#0e0e0e" media="(prefers-color-scheme: dark)">
<meta name="theme-color" content="#f2f2f2" media="(prefers-color-scheme: light)">
<meta name="description" content="Send files between devices on the same network. Peer to peer, nothing uploaded.">
<meta name="robots" content="noindex, nofollow">
<link rel="icon" href="/favicon.ico" sizes="32x32">
<title>localdrop</title>
<style nonce="<?= $nonce ?>">
:root{--bg:#0e0e0e;--bg2:#131313;--bg3:#1b1b1b;--fg:#d7d7d7;--dim:#7d7d7d;--faint:#4f4f4f;--line:#262626;--line2:#3a3a3a;--bright:#fff;--err:#ff7b72;--shade:rgba(0,0,0,.62);--side:clamp(290px,27vw,356px)}
@media (prefers-color-scheme:light){:root{--bg:#f2f2f2;--bg2:#f9f9f9;--bg3:#e7e7e7;--fg:#202020;--dim:#6f6f6f;--faint:#a5a5a5;--line:#d8d8d8;--line2:#bdbdbd;--bright:#000;--err:#c62828;--shade:rgba(242,242,242,.72)}}
*{box-sizing:border-box;margin:0;padding:0}
[hidden]{display:none!important}
html{height:100%;-webkit-text-size-adjust:100%}
body{height:100%;overflow:hidden;background:var(--bg);color:var(--fg);font:15px/1.6 ui-monospace,"SF Mono","Cascadia Mono","JetBrains Mono",Menlo,Consolas,monospace;-webkit-font-smoothing:antialiased}
pre,code,kbd,input,textarea,button{font:inherit}
.sr{position:absolute;width:1px;height:1px;overflow:hidden;clip-path:inset(50%);white-space:nowrap}
.dim{color:var(--dim)}.b{color:var(--bright)}.sm{font-size:12.5px}
::selection{background:var(--fg);color:var(--bg)}
:focus-visible{outline:2px solid var(--bright);outline-offset:2px}
button{color:inherit;background:none;border:0;border-radius:0;cursor:pointer;-webkit-tap-highlight-color:transparent}
a{color:var(--bright);text-decoration:underline;text-decoration-thickness:1px;text-underline-offset:3px}
a:hover{background:var(--bright);color:var(--bg);text-decoration:none}
kbd{border:1px solid var(--line2);padding:0 4px;color:var(--fg);font-size:.92em}
.lnk{color:var(--dim);text-decoration:underline dotted;text-decoration-thickness:1px;text-underline-offset:3px;padding:0 2px;margin:0 -2px}
.lnk.hi{color:var(--bright)}
.lnk:hover{background:var(--fg);color:var(--bg);text-decoration:none}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:1ch;border:1px solid var(--line2);padding:8px 16px;line-height:1.3;white-space:nowrap;color:var(--fg);text-decoration:none;transition:border-color .12s,background-color .12s,color .12s}
.btn:hover{background:transparent;border-color:var(--fg);color:var(--bright)}
.btn.pri{background:var(--bright);border-color:var(--bright);color:var(--bg)}
.btn.pri:hover{background:var(--fg);border-color:var(--fg);color:var(--bg)}
.btn.sm{padding:4px 11px;font-size:12.5px}
.btn .k{opacity:.55;font-size:.85em}
.cur{animation:blink 1.1s steps(1) infinite}
.scroll{overflow:auto;overscroll-behavior:contain;scrollbar-width:thin;scrollbar-color:var(--line2) transparent}
.scroll::-webkit-scrollbar{width:8px;height:8px}
.scroll::-webkit-scrollbar-thumb{background:var(--line2)}
.scroll::-webkit-scrollbar-track{background:transparent}
.show-sm,.show-sm-b{display:none}
@keyframes blink{50%{opacity:0}}
@keyframes rise{from{opacity:0;transform:translateY(8px)}}
@keyframes fade{from{opacity:0}}
@keyframes pulse{50%{opacity:.3}}

/* shell: everything fits the viewport, only inner lists scroll */
.app{display:flex;flex-direction:column;height:100vh;height:100dvh;max-width:1640px;margin:0 auto}
.top{display:none}
.logo{color:var(--bright)}
.main{flex:1;min-height:0;display:grid;grid-template-columns:var(--side) minmax(0,1fr);grid-template-rows:minmax(0,1fr);column-gap:32px;padding:30px max(32px,env(safe-area-inset-right)) 26px max(32px,env(safe-area-inset-left))}
.side{display:flex;flex-direction:column;gap:26px;min-width:0;min-height:0;overflow-x:hidden;padding:12px 4px 4px;margin:-12px -4px -4px;container-type:inline-size}
.brand{flex:none}
.banner{color:var(--dim);font-size:clamp(7px,1.3vh,11px);line-height:1.18;white-space:pre;overflow:hidden;user-select:none;-webkit-user-select:none}
@supports (width:1cqi){.banner{font-size:clamp(6px,min(3.35cqi,1.35vh),12px)}}
.brand-logo{display:none;font-size:16px}
.lede{margin-top:14px;font-size:13.5px;line-height:1.55}
.stat{display:flex;align-items:center;gap:9px;min-width:0;font-size:12.5px;color:var(--dim)}
.stat .js-status{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.brand .stat{margin-top:8px}
.led{width:7px;height:7px;flex:none;background:var(--faint)}
.led.on{background:var(--bright);animation:pulse 2.4s ease-in-out infinite}
.led.off{background:var(--err)}
.notes{margin-top:auto;font-size:11.5px;line-height:1.7;color:var(--dim)}
.notes p+p{margin-top:8px}

/* boxes with a title notched into the border */
.box{position:relative;--box:var(--bg);background:var(--box);border:1px solid var(--line);padding:24px 20px 18px;min-width:0}
.ttl{position:absolute;top:0;left:14px;transform:translateY(-50%);background:var(--box);padding:0 8px;color:var(--dim);font-size:12.5px;line-height:1.5;white-space:nowrap}
.ttl.r{left:auto;right:14px}
.ttl b{font-weight:400;color:var(--bright)}
.ttl-b{color:inherit;font-size:inherit;line-height:inherit}
.ttl-b:hover{color:var(--fg)}

/* this device */
.me,.send{flex:none}
.me-in{display:flex;align-items:center;gap:16px}
.me-ic .icon{font-size:11px}
.me-info{flex:1;min-width:0}
.me-name{display:flex;flex-wrap:wrap;align-items:baseline;gap:2px 12px;font-size:16px;line-height:1.35}
.me-name>span{color:var(--bright);overflow-wrap:anywhere}
.me-name .lnk{font-size:12.5px}
.me-sub{margin-top:3px;font-size:12.5px;color:var(--dim)}
.me-foot{margin-top:14px;padding-top:10px;border-top:1px dotted var(--line)}
.tog{display:inline-flex;gap:1ch;text-align:left;font-size:12.5px;color:var(--dim);padding:0 2px;margin:0 -2px}
.tog:hover{background:var(--fg);color:var(--bg)}
.tog-box{color:var(--fg)}
.tog[aria-checked=true] .tog-box{color:var(--bright)}
.tog:hover .tog-box{color:inherit}
.inl{color:var(--bright);background:transparent;border:0;border-bottom:1px solid var(--line2);border-radius:0;outline:none;padding:0 2px;width:min(22ch,100%);min-width:0}
.inl:focus{border-bottom-color:var(--bright)}
.inl.bad{border-bottom-color:var(--err)}

/* ascii devices */
.icon{font-size:12.5px;line-height:1.16;color:var(--dim);white-space:pre;flex:none;user-select:none;-webkit-user-select:none;transition:color .15s}
.icon .scr{color:var(--bright)}

/* send */
.drop{border-style:dashed;border-color:var(--line2);transition:border-color .15s,background-color .15s}
.drop.hot{border-color:var(--bright);--box:var(--bg2)}
.drop-idle{display:flex;align-items:center;gap:18px}
.glyph{font-size:11.5px;line-height:1.16;color:var(--dim);white-space:pre;flex:none;user-select:none;-webkit-user-select:none;transition:color .15s,transform .2s}
.drop.hot .glyph{color:var(--bright);transform:translateY(-4px)}
.big{color:var(--bright);font-size:15px;line-height:1.45}
.drop-idle .sm{margin-top:5px;line-height:1.55}
.send-acts{display:flex;flex-wrap:wrap;gap:8px;margin-top:16px}
.send-acts .btn{flex:1 1 112px;padding:8px 6px;font-size:14px}
.row-sb{display:flex;justify-content:space-between;align-items:baseline;gap:6px 12px;flex-wrap:wrap}
.files{list-style:none;margin-top:10px;font-size:12.5px}
.files li{display:flex;align-items:baseline;gap:10px;padding:4px 0;border-top:1px dotted var(--line)}
.files .n{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.rm{flex:none;color:var(--dim);padding:0 5px}
.rm:hover{background:var(--fg);color:var(--bg)}
.to{display:flex;flex-wrap:wrap;align-items:center;gap:8px;margin-top:14px;font-size:12.5px;min-width:0}
.chip{border:1px solid var(--line2);padding:4px 11px;color:var(--fg);max-width:100%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.chip:hover,.chip.pri{background:var(--bright);border-color:var(--bright);color:var(--bg)}
.chip.pri:hover{background:var(--fg);border-color:var(--fg)}
textarea{display:block;width:100%;min-height:92px;max-height:30vh;color:var(--fg);background:var(--bg2);border:1px solid var(--line2);border-radius:0;padding:9px 11px;resize:vertical;outline:none;font-size:14px;line-height:1.55}
textarea:focus{border-color:var(--fg)}
textarea::placeholder{color:var(--faint)}

/* activity: transfers + received */
.act{display:flex;flex-direction:column;flex:0 1 auto;min-height:104px;padding:20px 0 2px;animation:fade .25s ease both}
.act.shut{min-height:0;padding:12px 0 0}
.act.shut .act-body{display:none}
.act-body{flex:1 1 auto;min-height:0;padding:2px 18px 12px}
.txs,.rxs{list-style:none}
.txs:not(:empty)+.rxs:not(:empty){margin-top:8px;padding-top:2px;border-top:1px dashed var(--line2)}
.tx{padding:10px 0;border-top:1px dotted var(--line);transition:opacity .4s}
.tx:first-child{border-top:0}
.tx.gone{opacity:0}
.tx-1{display:flex;align-items:baseline;gap:9px}
.tx-what{flex:1;min-width:0;color:var(--bright);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.tx-b{flex:none;font-size:12px;color:var(--dim);text-decoration:underline dotted;text-underline-offset:3px;padding:0 2px}
.tx-b:hover{background:var(--fg);color:var(--bg);text-decoration:none}
.tx-2{font-size:12px;color:var(--dim);margin-top:1px;overflow-wrap:anywhere}
.tx.bad .tx-2{color:var(--err)}
.tx-3{font-size:12px;color:var(--dim);margin-top:5px;white-space:pre}
.tx-3 i{font-style:normal;color:var(--bright)}
.rxs>li{display:flex;align-items:center;gap:12px;padding:10px 0;border-top:1px dotted var(--line);animation:rise .3s ease both}
.rxs>li:first-child{border-top:0}
.rxs>li.nt{display:block}
.thumb{width:40px;height:40px;flex:none;object-fit:cover;border:1px solid var(--line);background:var(--bg3)}
.ph{display:grid;place-items:center;font-size:10.5px;color:var(--dim);overflow:hidden}
.rx-main{flex:1;min-width:0}
.rx-n{color:var(--bright);font-size:13.5px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.rx-l2{display:flex;align-items:baseline;gap:10px;min-width:0}
.rx-m{flex:1;min-width:0;font-size:11.5px;color:var(--dim);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.rx-a{flex:none;font-size:12px;color:var(--dim)}
.note{margin-top:6px;padding:8px 10px;border:1px solid var(--line);background:var(--bg2);white-space:pre-wrap;overflow-wrap:anywhere;max-height:9.5em;font-size:13px;line-height:1.55;color:var(--fg)}

/* nearby */
.near{display:flex;flex-direction:column;min-height:0;padding:20px 10px 10px}
.near-body{flex:1;min-height:0;display:flex;padding:14px;background:radial-gradient(circle,var(--line) 1px,transparent 1.6px) center/22px 22px;background-attachment:local}
.grid-wrap{margin:auto;width:100%}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(172px,200px));justify-content:center;gap:16px}
.card{position:relative;display:flex;flex-direction:column;border:1px solid var(--line);background:var(--bg2);animation:rise .35s cubic-bezier(.2,.8,.2,1) both;transition:border-color .15s,background-color .15s}
.card::after{content:"";position:absolute;inset:-1px;pointer-events:none;opacity:0;transition:opacity .15s;--c:var(--bright);background:linear-gradient(var(--c),var(--c)) 0 0/10px 1px,linear-gradient(var(--c),var(--c)) 0 0/1px 10px,linear-gradient(var(--c),var(--c)) 100% 0/10px 1px,linear-gradient(var(--c),var(--c)) 100% 0/1px 10px,linear-gradient(var(--c),var(--c)) 0 100%/10px 1px,linear-gradient(var(--c),var(--c)) 0 100%/1px 10px,linear-gradient(var(--c),var(--c)) 100% 100%/10px 1px,linear-gradient(var(--c),var(--c)) 100% 100%/1px 10px;background-repeat:no-repeat}
.card:hover{border-color:var(--line2)}
.card:hover::after,.card:focus-within::after,.card.ready::after{opacity:1}
.card.ready{border-color:var(--line2)}
.card.ready::after{animation:pulse 1.8s ease-in-out infinite}
.card:hover .icon{color:var(--fg)}
.card.over{background:var(--bright);border-color:var(--bright)}
.card.over *{color:var(--bg)!important;border-color:transparent!important}
.card.over::after{animation:none;opacity:0}
.hit{display:flex;flex-direction:column;align-items:center;gap:7px;width:100%;padding:12px 12px 14px;text-align:center}
.hit:focus-visible{outline-offset:-4px}
.tag{align-self:stretch;font-size:11px;color:var(--dim);text-align:left;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.nm{max-width:100%;color:var(--bright);font-size:14.5px;line-height:1.3;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.card.away .nm{color:var(--fg)}
.st{max-width:100%;font-size:12px;color:var(--dim);min-height:1.5em;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.st.live{color:var(--bright)}
.st.err{color:var(--err)}
.card-acts{display:flex;border-top:1px solid var(--line)}
.card-acts button{flex:1;padding:7px 0;font-size:12px;color:var(--dim);transition:background-color .12s,color .12s}
.card-acts button+button{border-left:1px solid var(--line)}
.card-acts button:hover{background:var(--fg);color:var(--bg)}
.empty{margin:auto;display:flex;align-items:center;justify-content:center;gap:44px;flex-wrap:wrap;padding:8px}
.radar{position:relative;flex:none;font-size:13px;line-height:1.15;user-select:none;-webkit-user-select:none}
.radar pre{white-space:pre;color:var(--dim)}
.radar .hi{position:absolute;inset:0;color:var(--bright)}
.empty-t{max-width:42ch;min-width:0}
.empty-t>*+*{margin-top:12px}
.qr-row{display:flex;align-items:center;gap:16px}
.qr{display:block;width:120px;height:120px;flex:none}

/* overlays */
.toasts{position:fixed;top:16px;left:50%;transform:translateX(-50%);z-index:80;display:flex;flex-direction:column;align-items:center;gap:8px;width:min(520px,calc(100vw - 24px));pointer-events:none}
.toast{max-width:100%;padding:8px 14px;background:var(--fg);color:var(--bg);font-size:13px;line-height:1.5;animation:fade .2s ease both;transition:opacity .3s}
.toast.err{background:var(--err)}
.toast.out{opacity:0}
.ov{position:fixed;inset:0;z-index:60;display:grid;place-items:center;padding:16px;background:var(--shade);-webkit-backdrop-filter:blur(4px);backdrop-filter:blur(4px);animation:fade .18s ease both}
#askOv{z-index:65}
.modal{width:min(440px,100%);--box:var(--bg2);border-color:var(--line2);box-shadow:0 30px 80px -30px rgba(0,0,0,.8);animation:rise .24s cubic-bezier(.2,.8,.2,1) both}
.mbody{max-height:calc(100vh - 90px);max-height:calc(100dvh - 90px)}
.x{position:absolute;top:6px;right:8px;padding:2px 8px;font-size:12px;color:var(--dim)}
.x:hover{background:var(--fg);color:var(--bg)}
.ask{text-align:center}
.ask .icon{display:inline-block;text-align:left}
.ask-t{margin-top:12px}
.ask-what{margin-top:4px;color:var(--bright);font-size:18px;line-height:1.35;overflow-wrap:anywhere}
.ask-size{color:var(--dim);font-size:13px;overflow-wrap:anywhere}
.ask-exp{margin-top:14px;font-size:12px;color:var(--dim);white-space:pre}
.ask-auto{margin-top:12px;font-size:12px;color:var(--dim);text-align:left}
.ask-auto:hover{color:var(--fg)}
.ask-auto[aria-pressed=true]{color:var(--bright)}
.ask-acts{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:18px}
.ask-more{margin-top:12px;font-size:12px;color:var(--dim)}
.pair-top{display:flex;gap:18px;align-items:flex-start}
.pair .qr{width:148px;height:148px}
.url{display:block;margin-top:10px;padding:7px 10px;border:1px solid var(--line);background:var(--bg);font-size:12px;color:var(--fg);overflow-wrap:anywhere;user-select:all;-webkit-user-select:all}
.acts{display:flex;flex-wrap:wrap;gap:10px;margin-top:14px}
.sep{border:0;border-top:1px dashed var(--line2);margin:20px 0 16px}
.pair p+p{margin-top:6px}
.join{display:flex;flex-wrap:wrap;align-items:center;gap:10px;margin-top:16px;font-size:13px}
.veil{position:fixed;inset:10px;z-index:50;border:1px dashed var(--bright);pointer-events:none;display:flex;align-items:flex-end;justify-content:center;padding:18px}
.veil span{background:var(--bright);color:var(--bg);padding:3px 10px;font-size:13px}

@media (hover:none){.on-hover,.k,.keys{display:none}}
@media (hover:hover){.on-touch{display:none}}
@media (min-width:760px) and (max-width:1100px){
  :root{--side:clamp(268px,33vw,320px)}
  .main{column-gap:22px;padding:24px 22px 20px}
  .grid{grid-template-columns:repeat(auto-fit,minmax(160px,196px));gap:12px}
}
@media (min-width:760px) and (max-height:760px){
  .lede,.notes p:first-child{display:none}
  .main{padding-top:24px;padding-bottom:18px}
  .side{gap:22px}
}
@media (min-width:760px) and (max-height:600px){
  .banner{display:none}
  .brand-logo{display:block}
}
@media (min-width:760px) and (max-height:520px){
  .main{padding-top:18px;padding-bottom:10px}
  .me-ic,.drop-idle,.notes{display:none}
  .send-acts{margin-top:0}
}
@media (max-width:759px){
  body{font-size:14px}
  .top{display:flex;align-items:center;justify-content:space-between;gap:14px;flex:none;min-height:46px;padding:env(safe-area-inset-top) max(16px,env(safe-area-inset-right)) 0 max(16px,env(safe-area-inset-left));border-bottom:1px solid var(--line)}
  .main{display:flex;flex-direction:column;gap:20px;overflow-y:auto;overflow-x:hidden;overscroll-behavior:contain;padding:20px max(12px,env(safe-area-inset-right)) calc(12px + env(safe-area-inset-bottom)) max(12px,env(safe-area-inset-left))}
  .side{display:contents}
  .brand,.notes,.me-ic,.drop-idle,.tag,.hide-sm{display:none}
  .show-sm{display:inline}
  .show-sm-b{display:block}
  .box{padding:22px 14px 14px}
  .me{order:1;display:flex;flex-wrap:wrap;align-items:flex-end;justify-content:space-between;gap:4px 14px}
  .me-in{flex:1 1 auto;min-width:0}
  .me-foot{margin:0;padding:0;border:0}
  .me-name{font-size:15.5px}
  .near{order:2;flex:1 1 auto;min-height:230px;padding:18px 4px 4px}
  .act{order:3;max-height:34vh;max-height:34dvh;min-height:0;padding:18px 0 0}
  .send{order:4}
  .send-acts{margin-top:0}
  .near-body{padding:10px}
  .grid{grid-template-columns:repeat(auto-fit,minmax(138px,220px));gap:10px}
  .icon{font-size:10.5px}
  .hit{padding:12px 8px 10px;gap:5px}
  .nm{font-size:14px}
  .empty{flex-direction:column;gap:16px;text-align:center}
  .radar{font-size:10px}
  .qr-row{display:none}
  .act-body{padding:2px 14px 10px}
  .pair-top{flex-direction:column;align-items:center;text-align:center}
  .toasts{top:54px}
}
@media (prefers-reduced-motion:reduce){*,*::before,*::after{animation:none!important;transition:none!important}}
</style>
</head>
<body>
<div class="app" id="app">
<header class="top">
  <span class="logo">localdrop<span class="cur" aria-hidden="true">_</span></span>
  <span class="stat" role="status"><span class="led js-led" aria-hidden="true"></span><span class="js-status">connecting…</span></span>
</header>
<main class="main">
<div class="side scroll">
  <div class="brand">
<pre class="banner" aria-hidden="true">    __                 __    __
   / /___  _________ _/ /___/ /________  ____
  / / __ \/ ___/ __ `/ / __  / ___/ __ \/ __ \
 / / /_/ / /__/ /_/ / / /_/ / /  / /_/ / /_/ /
/_/\____/\___/\__,_/_/\__,_/_/   \____/ .___/
                                     /_/</pre>
    <p class="logo brand-logo">localdrop<span class="cur" aria-hidden="true">_</span></p>
    <h1 class="sr">localdrop</h1>
    <p class="lede">send files between your devices. nothing gets uploaded: files go straight from one browser to the other.</p>
    <p class="stat" role="status"><span class="led js-led" aria-hidden="true"></span><span class="js-status">connecting…</span></p>
  </div>

  <section class="box me" aria-label="this device">
    <span class="ttl">this device</span>
    <div class="me-in">
      <div class="me-ic" id="meIc"></div>
      <div class="me-info">
        <div class="me-name" id="meRow"><span id="meName"></span><button class="lnk" id="renameBtn" type="button">rename</button></div>
        <form class="me-name" id="renameForm" hidden><input class="inl" id="renameIn" maxlength="32" autocomplete="off" spellcheck="false" aria-label="device name"><button class="lnk" type="submit">save</button><button class="lnk" id="renameCancel" type="button">cancel</button></form>
        <div class="me-sub" id="meSub"></div>
      </div>
    </div>
    <div class="me-foot"><button class="tog" id="saveBtn" type="button" role="switch" aria-checked="false"><span class="tog-box" id="saveBox" aria-hidden="true">[ ]</span><span>auto-save incoming files</span></button></div>
  </section>

  <section class="box send drop" id="drop" aria-label="send">
    <span class="ttl">send</span>
    <div id="dropIdle">
      <div class="drop-idle">
<pre class="glyph" aria-hidden="true">    /\
   /  \
  /_  _\
    ||
 ___||___
|________|</pre>
        <div>
          <p class="big on-hover">drop files anywhere</p>
          <p class="big on-touch">pick files, then a device</p>
          <p class="dim sm on-hover">or paste with <kbd class="mod">ctrl</kbd>+<kbd>v</kbd>. text and screenshots work too.</p>
          <p class="dim sm on-touch">or write a quick note.</p>
        </div>
      </div>
      <div class="send-acts"><button class="btn pri" id="chooseBtn" type="button">choose files</button><button class="btn" id="noteBtn" type="button">write a note</button></div>
    </div>
    <div id="dropStaged" hidden>
      <div class="row-sb"><p><span class="dim">ready:</span> <span class="b" id="stagedHead"></span></p><span class="sm"><button class="lnk" id="stagedAdd" type="button">add more</button> · <button class="lnk" id="stagedClear" type="button">clear</button></span></div>
      <ul class="files" id="stagedList"></ul>
      <div class="to" id="stagedTo"></div>
    </div>
    <div id="dropNote" hidden>
      <textarea id="noteText" rows="4" maxlength="20000" placeholder="type or paste text, a link, a code…" aria-label="note"></textarea>
      <div class="row-sb"><div class="to" id="noteTo"></div><button class="lnk sm" id="noteCancel" type="button">cancel</button></div>
    </div>
  </section>

  <section class="box act" id="act" hidden aria-labelledby="actT">
    <span class="ttl"><button class="ttl-b" id="actT" type="button" aria-expanded="true">activity <span id="actSign" aria-hidden="true">[-]</span></button></span>
    <span class="ttl r" id="actTools" hidden><button class="lnk" id="rxSaveAll" type="button">save all</button> · <button class="lnk" id="rxClear" type="button">clear</button></span>
    <div class="act-body scroll"><ul class="txs" id="txs"></ul><ul class="rxs" id="rxs"></ul></div>
  </section>

  <footer class="notes">
    <p>file contents go straight between devices and are never uploaded. the server only relays the connection handshake, plus the names and sizes shown in the accept prompt.</p>
    <p class="keys"><kbd>f</kbd> files · <kbd>t</kbd> note · <kbd>c</kbd> connect · <kbd>y</kbd>/<kbd>n</kbd> answer · <kbd class="mod">ctrl</kbd>+<kbd>v</kbd> paste · <kbd>esc</kbd> clear</p>
  </footer>
</div>

<section class="box near" aria-labelledby="devT">
  <span class="ttl" id="devT">nearby<b id="devN"></b></span>
  <span class="ttl r"><button class="lnk hi" id="pairBtn" type="button"><span class="hide-sm">+ connect a device</span><span class="show-sm">+ connect</span></button></span>
  <div class="near-body scroll">
    <div class="grid-wrap" id="devWrap" hidden><div class="grid" id="devs"></div></div>
    <div class="empty" id="empty">
      <div class="radar" aria-hidden="true"><pre id="radLo"></pre><pre class="hi" id="radHi"></pre></div>
      <div class="empty-t" id="emptyT"></div>
    </div>
  </div>
</section>
</main>
</div>

<div class="toasts" id="toasts" aria-live="polite"></div>

<div class="ov" id="askOv" hidden>
  <div class="modal box ask" role="alertdialog" aria-modal="true" aria-labelledby="askT" aria-describedby="askWhat">
    <span class="ttl">incoming</span>
    <div id="askIc"></div>
    <p class="ask-t" id="askT"></p>
    <p class="ask-what" id="askWhat"></p>
    <p class="ask-size" id="askSize"></p>
    <p class="ask-exp" id="askExp" aria-hidden="true"></p>
    <button class="ask-auto" id="askAuto" type="button" aria-pressed="false"><span id="askBox">[ ]</span> don't ask again for <span id="askAutoName"></span> until this page closes</button>
    <div class="ask-acts">
      <button class="btn" id="askNo" type="button">decline <span class="k">n</span></button>
      <button class="btn pri" id="askYes" type="button">accept <span class="k">y</span></button>
    </div>
    <p class="ask-more" id="askMore"></p>
  </div>
</div>

<div class="ov" id="pairOv" hidden>
  <div class="modal box pair" role="dialog" aria-modal="true" aria-labelledby="pairT">
    <span class="ttl" id="pairT">connect a device</span>
    <button class="x" id="pairX" type="button" aria-label="close">close ×</button>
    <div class="mbody scroll">
      <div class="pair-top">
        <div id="pairQr"></div>
        <div>
          <p>open this link on your other device, or scan the code with its camera.</p>
          <code class="url" id="pairUrl"></code>
          <div class="acts"><button class="btn sm pri" id="pairCopy" type="button">copy link</button><button class="btn sm" id="pairShare" type="button" hidden>share</button></div>
        </div>
      </div>
      <hr class="sep">
      <div id="pairRoom"></div>
      <form class="join" id="joinForm"><label class="dim" for="joinIn">have a code?</label><input class="inl" id="joinIn" maxlength="40" autocomplete="off" autocapitalize="off" spellcheck="false" placeholder="abcd-efgh"><button class="btn sm" type="submit">join</button></form>
    </div>
  </div>
</div>

<div class="veil" id="veil" hidden aria-hidden="true"><span>drop on a device to send · anywhere else to stage</span></div>
<input type="file" id="picker" multiple hidden>
<div class="sr" id="sr" aria-live="assertive"></div>

<script nonce="<?= $nonce ?>">
(() => {
'use strict';

const CFG = <?= $cfg ?>;
const API = location.pathname;
const READ = 1 << 20, HIGH = 4 << 20, LOW = 1 << 20, SPILL = 16 << 20, NOTE_MAX = 64 << 10, TEXT_MAX = 20000, MAX_FILES = 10000;
const ASK_MS = 60000, CONNECT_MS = 25000, BYE_MS = 20000;
const KINDS = ['phone', 'tablet', 'computer'];
const OSES = ['ios', 'android', 'windows', 'macos', 'linux', 'chromeos'];
const ID_RE = /^p[a-f0-9]{15}$/;
const NO_ROUTE = "couldn't connect. this network may block devices from reaching each other (guest wi-fi, client isolation).";
const TOUCH = matchMedia('(hover: none)').matches;
const TAP = TOUCH ? 'tap' : 'click';

/* ---------- helpers ---------- */
const $ = (id) => document.getElementById(id);
const now = () => performance.now();
const hex = (n) => Array.from(crypto.getRandomValues(new Uint8Array(n)), (b) => b.toString(16).padStart(2, '0')).join('');
const plural = (n, w) => n + ' ' + w + (n === 1 ? '' : 's');
const clamp01 = (f) => Math.min(1, Math.max(0, f || 0));
const pct = (f) => Math.floor(clamp01(f) * 100) + '%';
const cut = (s, n) => Array.from(String(s)).slice(0, n).join('');
const txt = (el, t) => { if (el.textContent !== t) el.textContent = t; };

function h(tag, props, ...kids) {
  const e = document.createElement(tag);
  for (const k in props || {}) {
    const v = props[k];
    if (v == null || v === false) continue;
    if (k === 'class') e.className = v;
    else if (k === 'text') e.textContent = v;
    else if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
    else e.setAttribute(k, v === true ? '' : String(v));
  }
  for (const c of kids) if (c != null && c !== false) e.append(c);
  return e;
}
const btn = (cls, text, on, more) => h('button', Object.assign({ class: cls, type: 'button', text, onclick: on }, more));

function fmtBytes(n) {
  const u = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  while (n >= 1024 && i < 4) { n /= 1024; i++; }
  return (i && n < 10 ? n.toFixed(1) : Math.round(n)) + ' ' + u[i];
}
function fmtTime(s) {
  if (!(s >= 1)) return 'under 1s';
  s = Math.round(s);
  if (s < 60) return s + 's';
  const m = Math.floor(s / 60);
  return m < 60 ? m + 'm ' + String(s % 60).padStart(2, '0') + 's' : Math.floor(m / 60) + 'h ' + String(m % 60).padStart(2, '0') + 'm';
}
const ago = (t) => { const s = (Date.now() - t) / 1000; return s < 50 ? 'just now' : s < 3600 ? Math.round(s / 60) + 'm ago' : Math.round(s / 3600) + 'h ago'; };
const cleanName = (s) => cut(String(s ?? '').replace(/[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u2028-\u202e\u2060-\u206f\ufeff]/g, '').replace(/\s+/g, ' ').trim(), 32).trim();
const safeName = (s) => cut(String(s ?? '').replace(/[\u0000-\u001f\u007f\u200b-\u200f\u202a-\u202e\u2066-\u2069\\/:*?"<>|]+/g, '_').replace(/^\s+|[\s.]+$/g, ''), 160) || 'file';
function safeMime(m) {
  m = String(m || '').toLowerCase();
  return /^(image\/(png|jpeg|gif|webp|avif|heic|heif|bmp)|video\/[\w.+-]+|audio\/[\w.+-]+|application\/pdf|text\/plain)$/.test(m) ? m : 'application/octet-stream';
}
const extOf = (n) => { const m = /\.([a-z0-9]{1,5})$/i.exec(n); return m ? '.' + m[1].toLowerCase() : 'file'; };

/* ---------- identity, settings, room ---------- */
const store = {
  get: (k) => { try { return localStorage.getItem('localdrop.' + k); } catch { return null; } },
  set: (k, v) => { try { localStorage.setItem('localdrop.' + k, v); } catch {} },
};
const ADJ = ['quiet', 'brave', 'cosmic', 'velvet', 'amber', 'lunar', 'swift', 'mellow', 'crimson', 'jade', 'solar', 'misty', 'nimble', 'golden', 'silent', 'electric', 'wild', 'cobalt'];
const ANI = ['otter', 'falcon', 'lynx', 'heron', 'panda', 'wolf', 'koala', 'bison', 'raven', 'tapir', 'gecko', 'marten', 'ferret', 'orca', 'moth', 'newt', 'stork', 'fox'];
const pick = (a) => a[crypto.getRandomValues(new Uint32Array(1))[0] % a.length];
const ua = navigator.userAgent || '';
const touchMac = /Macintosh/.test(ua) && navigator.maxTouchPoints > 1;

// The secret is per tab and per page load, so two tabs never steal each other's messages.
const me = {
  secret: hex(24),
  name: cleanName(store.get('name')),
  kind: /iPad|Tablet/i.test(ua) || touchMac || (/Android/i.test(ua) && !/Mobile/i.test(ua)) ? 'tablet'
    : (navigator.userAgentData && navigator.userAgentData.mobile) || /Mobi|iPhone|iPod|Android/i.test(ua) ? 'phone' : 'computer',
  os: /iPhone|iPad|iPod/.test(ua) || touchMac ? 'ios' : /Android/i.test(ua) ? 'android' : /CrOS/.test(ua) ? 'chromeos'
    : /Windows/.test(ua) ? 'windows' : /Mac OS X|Macintosh/.test(ua) ? 'macos' : /Linux/.test(ua) ? 'linux' : '',
};
if (!me.name) { me.name = pick(ADJ) + ' ' + pick(ANI); store.set('name', me.name); }
const savedPref = store.get('autosave');
let autoSave = savedPref === null ? me.kind === 'computer' : savedPref === '1';
const MOD = me.os === 'macos' || me.os === 'ios' ? '⌘' : 'ctrl';

const ABC = 'abcdefghjkmnpqrstuvwxyz23456789';
const normCode = (v) => String(v || '').toLowerCase().replace(/[^a-z0-9]/g, '');
const validCode = (v) => /^[a-z0-9]{6,32}$/.test(v);
const pretty = (c) => c.replace(/(.{4})(?=.)/g, '$1-');
const newCode = () => Array.from(crypto.getRandomValues(new Uint8Array(8)), (b) => ABC[b % ABC.length]).join('');
function hashRoom() {
  let v = '';
  try { v = decodeURIComponent(location.hash.slice(1)); } catch {}
  v = normCode(v);
  return validCode(v) ? v : '';
}
let room = hashRoom();

/* ---------- state ---------- */
const peers = new Map();   // id -> device card
const conns = new Map();   // connection id -> transfer
const ended = new Map();   // recently closed connection ids (ignore late duplicates)
const stray = new Map();   // ICE that arrived before its offer
const outbox = [], received = [], asks = [], modals = [];
const autoAccept = new Set();
let lastSeq = 0, online = null, offWhy = '', staged = null, composer = null, dragId = null, ticks = 0;
let askCur = null, autoOn = false, lastFocus = null;

function toast(text, bad) {
  const box = $('toasts'), el = h('div', { class: 'toast' + (bad ? ' err' : ''), text });
  box.append(el);
  while (box.children.length > 3) box.firstChild.remove();
  setTimeout(() => { el.classList.add('out'); setTimeout(() => el.remove(), 320); }, bad ? 6500 : 3800);
}
function say(t) { const s = $('sr'); s.textContent = ''; setTimeout(() => { s.textContent = t; }, 50); }

/* ---------- relay ---------- */
async function api(body) {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), 10000);
  try {
    const res = await fetch(API, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body), cache: 'no-store', credentials: 'same-origin', signal: ctl.signal });
    let d = null;
    try { d = await res.json(); } catch {}
    if (!res.ok || !d || d.ok !== true) { const e = new Error((d && d.error) || 'http ' + res.status); e.status = res.status; throw e; }
    return d;
  } finally { clearTimeout(t); }
}

const leds = document.querySelectorAll('.js-led'), stats = document.querySelectorAll('.js-status');
function setOnline(ok, why) {
  online = ok;
  offWhy = ok ? '' : why || '';
  leds.forEach((e) => { e.className = 'led js-led ' + (ok ? 'on' : 'off'); });
  paintStatus();
}
function paintStatus() {
  const n = peers.size;
  const t = online === null ? 'connecting…'
    : online === false ? offWhy || 'offline · retrying…'
    : (room ? 'room ' + pretty(room) : 'this network') + ' · ' + (n ? plural(n, 'device') : 'no devices yet');
  stats.forEach((e) => txt(e, t));
}

let polling = false, again = false, pollT = 0, fails = 0;
const busy = () => outbox.length > 0 || [...conns.values()].some((c) => !c.dead && (c.state === 'connecting' || (c.state === 'asking' && c.role === 'send')));
function schedule(ms) {
  clearTimeout(pollT);
  if (ms == null) ms = document.hidden ? 4000 : busy() ? 400 : 2000;
  if (fails) ms = Math.max(ms, Math.min(15000, 1000 * 2 ** Math.min(fails - 1, 4)));
  pollT = setTimeout(poll, ms);
}
function pollNow() { if (polling) again = true; else schedule(0); }
function kick() { if (!polling) schedule(); }

async function poll() {
  clearTimeout(pollT);
  if (polling) return;
  polling = true;
  const asked = room;
  try {
    const r = await api({ a: 'poll', s: me.secret, room, name: me.name, kind: me.kind, os: me.os, bg: document.hidden, ack: lastSeq });
    if (asked !== room) return;
    fails = 0;
    setOnline(true);
    reconcile(Array.isArray(r.peers) ? r.peers : []);
    for (const m of Array.isArray(r.msgs) ? r.msgs : []) {
      if (!m || typeof m.q !== 'number' || m.q <= lastSeq) continue;
      lastSeq = m.q;
      try { onSignal(String(m.f || ''), m.d); } catch (e) { console.warn(e); }
    }
  } catch (e) {
    fails++;
    setOnline(false, e.status === 429 ? (e.message === 'room is full' ? 'this room is full' : 'too many requests · slowing down')
      : e.status >= 500 ? 'server error: ' + e.message : '');
  } finally {
    polling = false;
    const a = again;
    again = false;
    schedule(a ? 0 : undefined);
    const t = Date.now();
    for (const [k, v] of ended) if (t - v > 180000) ended.delete(k);
    for (const [k, v] of stray) if (t - v.t > 30000) stray.delete(k);
  }
}

// Signals go out in order, batched, and are retried until the relay takes them.
// Each one remembers its room, so nothing leaks into a room joined later.
let flushing = false, flushT = 0, flushFails = 0;
function signal(to, d) { outbox.push({ to, d, room }); if (!flushT && !flushing) flushT = setTimeout(flush, 25); }
const keep = (m) => m.room === room && (m.d.k === 'cancel' || m.d.k === 'decline' || (conns.has(m.d.c) && !conns.get(m.d.c).dead));
async function flush() {
  flushT = 0;
  if (flushing) return;
  while (outbox.length && outbox[0].room !== room) outbox.shift();
  if (!outbox.length) return;
  flushing = true;
  const r0 = room, batch = [];
  while (batch.length < 24 && outbox.length && outbox[0].room === r0) batch.push(outbox.shift());
  let wait = 0;
  try {
    const r = await api({ a: 'send', s: me.secret, room: r0, msgs: batch.map((m) => ({ to: m.to, d: m.d })) });
    flushFails = 0;
    const res = Array.isArray(r.res) ? r.res : [];
    batch.forEach((m, i) => { if (res[i] !== 1) undelivered(m, res[i]); });
  } catch (e) {
    if (e.status === 400) batch.forEach((m) => undelivered(m, -1));
    else {
      if (e.status === 409) pollNow();
      flushFails++;
      wait = Math.min(8000, 300 * 2 ** Math.min(flushFails, 5));
      outbox.unshift(...batch.filter(keep));
    }
  } finally {
    flushing = false;
    if (outbox.length) flushT = setTimeout(flush, wait);
  }
}
function undelivered(m, code) {
  const c = conns.get(m.d.c);
  if (c && !c.dead && m.d.k !== 'cancel' && m.d.k !== 'decline') fail(c, code === 0 ? c.peerName + ' went offline' : "couldn't reach " + c.peerName, false);
}

function onSignal(from, d) {
  if (!d || typeof d !== 'object' || typeof d.c !== 'string' || !ID_RE.test(from)) return;
  if (d.k === 'offer') return void onOffer(from, d);
  const c = conns.get(d.c);
  if (!c || c.peer !== from) {
    if (d.k === 'ice' && Array.isArray(d.list) && !ended.has(d.c) && stray.size < 64) {
      const s = stray.get(d.c) || { t: Date.now(), from, list: [] };
      if (s.from === from && s.list.length < 64) { s.list.push(...d.list.slice(0, 32)); stray.set(d.c, s); }
    }
    return;
  }
  if (d.k === 'answer') onAnswer(c, d);
  else if (d.k === 'ice') addIce(c, Array.isArray(d.list) ? d.list : []);
  else if (d.k === 'decline') fail(c, c.peerName + (d.why === 'busy' ? ' is busy, try again shortly' : d.why === 'expired' ? " didn't answer" : ' declined'), false);
  else if (d.k === 'cancel') fail(c, c.peerName + ' cancelled', false);
}

/* ---------- connections ---------- */
function makeConn(id, peer, role) {
  const pc = new RTCPeerConnection({ iceServers: CFG.ice });
  const p = peers.get(peer);
  const c = {
    id, peer, role, pc, peerName: p ? p.name : 'the other device', state: 'new', dead: false, ch: null, opened: false,
    remoteSet: false, sigReady: false, iceOut: [], iceIn: [], iceT: 0, timer: 0, discT: 0, goneAt: 0, askEnd: 0,
    what: null, files: null, isText: false, manifest: null, label: '', total: 0, count: 0, sent: 0, done: 0,
    rx: null, got: [], announced: 0, file: '', t0: 0, endAt: 0, rate: 0, mark: null, ui: null, error: '',
  };
  pc.onicecandidate = (e) => {
    if (!e.candidate || c.dead) return;
    c.iceOut.push(e.candidate.toJSON());
    if (c.sigReady && !c.iceT) c.iceT = setTimeout(() => flushIce(c), 60);
  };
  const onState = () => {
    if (c.dead) return;
    const s = pc.connectionState || pc.iceConnectionState;
    if (s === 'connected' || s === 'completed') { clearTimeout(c.discT); c.discT = 0; }
    else if (s === 'disconnected' && !c.discT) c.discT = setTimeout(() => fail(c, 'lost the connection to ' + c.peerName), 8000);
    else if (s === 'failed') fail(c, c.state === 'connecting' ? NO_ROUTE : 'lost the connection to ' + c.peerName);
  };
  if ('connectionState' in pc) pc.onconnectionstatechange = onState;
  else pc.oniceconnectionstatechange = onState;
  conns.set(id, c);
  return c;
}
function flushIce(c) { c.iceT = 0; while (c.iceOut.length && !c.dead) signal(c.peer, { k: 'ice', c: c.id, list: c.iceOut.splice(0, 16) }); }
function ready(c) { c.sigReady = true; if (c.iceOut.length) flushIce(c); }
function addIce(c, list) {
  for (const x of list.slice(0, 32)) {
    if (!x || typeof x.candidate !== 'string') continue;
    if (c.remoteSet) c.pc.addIceCandidate(x).catch(() => {});
    else if (c.iceIn.length < 64) c.iceIn.push(x);
  }
}
function gotRemote(c) { c.remoteSet = true; for (const x of c.iceIn.splice(0)) c.pc.addIceCandidate(x).catch(() => {}); }

async function startSend(peerId, what) {
  const peer = peers.get(peerId);
  if (!peer) return toast('that device is gone', true);
  const isText = typeof what.text === 'string';
  const files = isText ? [new File([what.text], 'note.txt', { type: 'text/plain' })] : Array.from(what.files || []).filter((f) => f instanceof File);
  if (!files.length) return;
  if (files.length > MAX_FILES) return toast('too many files at once (10,000 max). zip them first.', true);
  if (peer.bg) toast(peer.name + ' is in the background, so it may take a moment to answer');
  let c;
  try { c = makeConn(hex(12), peerId, 'send'); } catch (e) { return toast("couldn't start a connection: " + ((e && e.message) || e), true); }
  Object.assign(c, {
    what, files, isText, count: files.length, total: files.reduce((a, f) => a + f.size, 0), state: 'asking',
    label: isText ? 'a note' : files.length === 1 ? files[0].name : plural(files.length, 'file'),
  });
  paint(c);
  try {
    channel(c, c.pc.createDataChannel('localdrop', { ordered: true }));
    await c.pc.setLocalDescription(await c.pc.createOffer());
    if (c.dead) return;
    signal(peerId, { k: 'offer', c: c.id, sdp: c.pc.localDescription.sdp, m: { n: c.count, b: c.total, name: isText ? '' : cut(files[0].name, 120), text: isText } });
    ready(c);
    c.timer = setTimeout(() => fail(c, c.peerName + " didn't answer"), ASK_MS);
    kick();
  } catch { fail(c, "couldn't start the connection", false); }
}

async function onOffer(from, d) {
  if (conns.has(d.c) || ended.has(d.c) || typeof d.sdp !== 'string') return;
  const m = d.m && typeof d.m === 'object' ? d.m : {};
  if (!Number.isSafeInteger(m.n) || m.n < 1 || m.n > MAX_FILES || !Number.isSafeInteger(m.b) || m.b < 0) return;
  if (asks.length >= 5) return signal(from, { k: 'decline', c: d.c, why: 'busy' });
  let c;
  try { c = makeConn(d.c, from, 'recv'); } catch { return signal(from, { k: 'decline', c: d.c }); }
  const text = m.text === true;
  c.manifest = { n: m.n, b: m.b, text, name: safeName(m.name) };
  Object.assign(c, {
    count: m.n, total: m.b, state: 'asking', askEnd: Date.now() + ASK_MS - 5000,
    label: text ? 'a note' : m.n === 1 ? c.manifest.name : plural(m.n, 'file'),
  });
  c.pc.ondatachannel = (e) => { if (!c.dead && !c.ch) channel(c, e.channel); };
  const s = stray.get(d.c);
  if (s) { stray.delete(d.c); if (s.from === from) addIce(c, s.list); }
  const auto = autoAccept.has(from);
  if (!auto) showRequest(c);
  c.timer = setTimeout(() => {
    if (c.state !== 'asking') return;
    signal(c.peer, { k: 'decline', c: c.id, why: 'expired' });
    fail(c, 'request from ' + c.peerName + ' expired', false);
  }, ASK_MS - 5000);
  try {
    await c.pc.setRemoteDescription({ type: 'offer', sdp: d.sdp });
    if (c.dead) return;
    gotRemote(c);
    if (auto) accept(c);
  } catch {
    signal(from, { k: 'decline', c: d.c });
    fail(c, 'bad request from ' + c.peerName, false);
  }
}

async function accept(c) {
  if (c.dead || c.state !== 'asking') return;
  clearTimeout(c.timer);
  c.state = 'connecting';
  dropRequest(c);
  paint(c);
  try {
    for (let i = 0; !c.remoteSet && !c.dead; i++) { if (i > 100) throw new Error('slow'); await new Promise((r) => setTimeout(r, 50)); }
    if (c.dead) return;
    await c.pc.setLocalDescription(await c.pc.createAnswer());
    if (c.dead) return;
    signal(c.peer, { k: 'answer', c: c.id, sdp: c.pc.localDescription.sdp });
    ready(c);
    c.timer = setTimeout(() => fail(c, NO_ROUTE), CONNECT_MS);
    kick();
  } catch { fail(c, "couldn't answer " + c.peerName); }
}
function decline(c) {
  if (c.dead || c.state !== 'asking') return;
  signal(c.peer, { k: 'decline', c: c.id });
  fail(c, '', false);
}
async function onAnswer(c, d) {
  if (c.role !== 'send' || c.state !== 'asking' || typeof d.sdp !== 'string') return;
  clearTimeout(c.timer);
  c.state = 'connecting';
  paint(c);
  try {
    await c.pc.setRemoteDescription({ type: 'answer', sdp: d.sdp });
    if (c.dead) return;
    gotRemote(c);
    c.timer = setTimeout(() => fail(c, NO_ROUTE), CONNECT_MS);
  } catch { fail(c, 'handshake with ' + c.peerName + ' failed'); }
}

function channel(c, ch) {
  c.ch = ch;
  ch.binaryType = 'arraybuffer';
  ch.bufferedAmountLowThreshold = LOW;
  const open = () => {
    if (c.dead || c.opened) return;
    c.opened = true;
    clearTimeout(c.timer);
    c.state = 'transfer';
    c.t0 = now();
    c.mark = { t: c.t0, b: 0 };
    wake.hold();
    paint(c);
    if (c.role === 'send') pump(c).catch((e) => fail(c, e && e.message === 'read' ? "couldn't read " + (c.file || 'a file') : 'transfer failed'));
  };
  ch.onopen = open;
  if (ch.readyState === 'open') setTimeout(open, 0);
  ch.onmessage = (e) => { if (!c.dead) (c.role === 'send' ? fromReceiver : fromSender)(c, e.data); };
  ch.onclose = () => { if (!c.dead) fail(c, 'connection to ' + c.peerName + ' closed', false); };
}

/* sender: header, chunks, end; then wait for the receiver's "bye" before closing */
async function pump(c) {
  const ch = c.ch, mms = c.pc.sctp && c.pc.sctp.maxMessageSize;
  const size = mms > 0 ? Math.min(65536, mms) : 16384;
  for (const f of c.files) {
    if (c.dead) return;
    c.file = c.isText ? 'note' : f.name;
    ch.send(JSON.stringify({ t: 'file', name: cut(f.name, 200), size: f.size, mime: f.type || '' }));
    for (let off = 0; off < f.size;) {
      let buf;
      try { buf = await f.slice(off, Math.min(off + READ, f.size)).arrayBuffer(); } catch { throw new Error('read'); }
      if (!buf.byteLength) throw new Error('read');
      for (let p = 0; p < buf.byteLength; p += size) {
        if (ch.bufferedAmount > HIGH) await drained(c);
        if (c.dead) return;
        const n = Math.min(size, buf.byteLength - p);
        ch.send(new Uint8Array(buf, p, n));
        c.sent += n;
      }
      off += buf.byteLength;
    }
  }
  if (c.dead) return;
  ch.send(JSON.stringify({ t: 'end' }));
  c.state = 'finishing';
  let deadline = now() + BYE_MS;
  const iv = setInterval(() => {
    if (c.dead || c.state !== 'finishing') return clearInterval(iv);
    if (ch.bufferedAmount > 0) deadline = now() + BYE_MS;
    else if (now() > deadline) { clearInterval(iv); fail(c, c.peerName + ' never confirmed the transfer'); }
  }, 500);
}
function drained(c) {
  return new Promise((res) => {
    const ch = c.ch;
    const done = () => { ch.removeEventListener('bufferedamountlow', done); clearInterval(iv); res(); };
    ch.addEventListener('bufferedamountlow', done);
    const iv = setInterval(() => { if (c.dead || ch.readyState !== 'open' || ch.bufferedAmount <= LOW) done(); }, 200);
  });
}
function fromReceiver(c, data) {
  if (typeof data !== 'string') return;
  let m;
  try { m = JSON.parse(data); } catch { return; }
  if (m.t === 'bye' && c.state === 'finishing') finish(c);
  else if (m.t === 'cancel') fail(c, c.peerName + ' cancelled', false);
}

/* receiver: holds the sender to exactly what was announced in the request */
function fromSender(c, data) {
  if (typeof data === 'string') {
    let m;
    try { m = JSON.parse(data); } catch { return fail(c, 'garbled data from ' + c.peerName); }
    if (m.t === 'file') rxBegin(c, m);
    else if (m.t === 'end') rxEnd(c);
    else if (m.t === 'cancel') fail(c, c.peerName + ' cancelled', false);
    return;
  }
  const rx = c.rx;
  if (!(data instanceof ArrayBuffer) || !rx || rx.got + data.byteLength > rx.size) return fail(c, c.peerName + ' sent more than it announced');
  rx.chunks.push(data);
  rx.got += data.byteLength;
  rx.pend += data.byteLength;
  c.done += data.byteLength;
  // Move chunks out of the JS heap into blob storage every 16 MB so big files don't crash the tab.
  if (rx.pend >= SPILL) { rx.parts.push(new Blob(rx.chunks)); rx.chunks = []; rx.pend = 0; }
  if (rx.got === rx.size) rxFile(c);
}
function rxBegin(c, m) {
  const M = c.manifest;
  if (c.rx || c.got.length >= M.n || !Number.isSafeInteger(m.size) || m.size < 0 || c.announced + m.size > M.b) {
    return fail(c, c.peerName + " sent something it didn't announce");
  }
  c.announced += m.size;
  c.rx = { name: M.text ? 'note.txt' : safeName(m.name), size: m.size, mime: safeMime(m.mime), got: 0, chunks: [], parts: [], pend: 0 };
  c.file = M.text ? 'note' : c.rx.name;
  if (!m.size) rxFile(c);
}
function rxFile(c) {
  const rx = c.rx;
  c.rx = null;
  const item = { name: rx.name, size: rx.size, mime: rx.mime, from: c.peerName, t: Date.now(), blob: new Blob(rx.parts.concat(rx.chunks), { type: rx.mime }), url: '', text: null, file: null, agoEl: null };
  c.got.push(item);
  if (c.manifest.text && c.manifest.n === 1 && rx.size <= NOTE_MAX) {
    item.blob.text().then((t) => { item.text = t; addReceived(item); }, () => addReceived(item));
  } else {
    addReceived(item);
    if (autoSave) save(item);
  }
}
function rxEnd(c) {
  if (c.rx || c.got.length !== c.manifest.n || c.done !== c.manifest.b) return fail(c, 'the transfer from ' + c.peerName + ' was incomplete');
  try { c.ch.send(JSON.stringify({ t: 'bye' })); } catch {}
  finish(c);
}

function stop(c) { clearTimeout(c.timer); clearTimeout(c.discT); clearTimeout(c.iceT); c.timer = c.discT = c.iceT = 0; }
function flashPeer(id, ok, text) { const p = peers.get(id); if (p) p.flash = { ok, text, until: Date.now() + 4000 }; }
function finish(c) {
  if (c.dead) return;
  c.dead = true;
  c.state = 'finished';
  c.endAt = now();
  stop(c);
  paint(c);
  flashPeer(c.peer, true, c.role === 'send' ? 'sent' : 'received');
  say((c.role === 'send' ? 'sent ' : 'received ') + c.label);
  if (c.role === 'recv') toast('received ' + c.label + ' from ' + c.peerName);
  setTimeout(() => teardown(c), c.role === 'send' ? 300 : 10000);
  retire(c, 5000);
  wake.check();
}
function fail(c, msg, notify = true) {
  if (c.dead) return;
  const was = c.state;
  c.dead = true;
  c.state = 'failed';
  c.error = msg;
  stop(c);
  for (let i = outbox.length - 1; i >= 0; i--) if (outbox[i].d.c === c.id && !keep(outbox[i])) outbox.splice(i, 1);
  if (notify && was !== 'new') {
    if (c.ch && c.ch.readyState === 'open') { try { c.ch.send(JSON.stringify({ t: 'cancel' })); } catch {} }
    signal(c.peer, { k: 'cancel', c: c.id });
  }
  dropRequest(c);
  if (msg) {
    paint(c);
    flashPeer(c.peer, false, msg === 'cancelled' ? 'cancelled' : 'failed');
    say(msg);
    retire(c, c.role === 'send' && c.what ? 15000 : 9000);
  } else removeTx(c);
  setTimeout(() => teardown(c), 400);
  wake.check();
}
function teardown(c) {
  stop(c);
  try { if (c.ch) c.ch.close(); } catch {}
  try { c.pc.close(); } catch {}
  c.files = null;
  c.rx = null;
  if (conns.get(c.id) === c) conns.delete(c.id);
  ended.set(c.id, Date.now());
}

const active = () => [...conns.values()].filter((c) => !c.dead && (c.state === 'transfer' || c.state === 'finishing'));
const wake = {
  lock: null,
  async hold() {
    if (this.lock || document.hidden || !navigator.wakeLock) return;
    try { this.lock = await navigator.wakeLock.request('screen'); this.lock.addEventListener('release', () => { this.lock = null; }); } catch {}
  },
  check() { if (this.lock && !active().length) { this.lock.release().catch(() => {}); this.lock = null; } },
};
/* ---------- ascii devices ---------- */
const ICONS = {
  computer: { top: [' .---------. '], l: ' |', r: '| ', w: 9, rows: 3, bot: [" '---------' ", '/___________\\'] },
  tablet: { top: [' .---------. '], l: ' |', r: '| ', w: 9, rows: 4, bot: [" '----o----' "] },
  phone: { top: ['   .-----.   '], l: '   |', r: '|   ', w: 5, rows: 4, bot: ["   '--o--'   "] },
};
function buildIcon(kind) {
  const I = ICONS[kind] || ICONS.computer, scr = [];
  const pre = h('pre', { class: 'icon', 'aria-hidden': 'true' }, I.top.join('\n') + '\n');
  for (let r = 0; r < I.rows; r++) { const s = h('span', { class: 'scr' }); scr.push(s); pre.append(I.l, s, I.r + '\n'); }
  pre.append(I.bot.join('\n'));
  const ic = { pre, scr, I, last: null };
  drawScreen(ic, 'idle');
  return ic;
}
// The little screen shows what the device is doing: progress fills it, faces show the outcome.
function drawScreen(ic, mode, frac) {
  const { w, rows } = ic.I, mid = (rows - 1) >> 1, out = new Array(rows).fill(' '.repeat(w));
  const center = (s) => { out[mid] = (' '.repeat(Math.max(0, (w - s.length) >> 1)) + s).padEnd(w).slice(0, w); };
  if (mode === 'fill') {
    let left = Math.round(clamp01(frac) * w * rows);
    for (let r = rows - 1; r >= 0; r--) { const f = Math.min(w, Math.max(0, left)); out[r] = '#'.repeat(f) + ' '.repeat(w - f); left -= w; }
  } else if (mode === 'wait') center(['.  ', '.. ', '...', '   '][(ticks >> 1) % 4]);
  else if (mode === 'spin') center('-\\|/'[ticks % 4]);
  else if (mode === 'ask') center(ticks % 4 < 2 ? '?' : ' ');
  else if (mode === 'q') center('?');
  else if (mode === 'ok') center(':)');
  else if (mode === 'bad') center(':(');
  else if (mode === 'drop') center('drop');
  else if (mode === 'plus') center('+');
  else if (mode === 'you') center('you');
  const key = out.join('|');
  if (key === ic.last) return;
  ic.last = key;
  ic.scr.forEach((s, i) => { s.textContent = out[i]; });
}

/* ---------- devices ---------- */
const tagOf = (p) => p.kind + (p.os ? ' · ' + p.os : '');
function reconcile(list) {
  const seen = new Set();
  let changed = false;
  for (const p of list) {
    if (!p || typeof p.id !== 'string' || !ID_RE.test(p.id) || seen.has(p.id)) continue;
    seen.add(p.id);
    const name = cleanName(p.name) || 'device', kind = KINDS.includes(p.kind) ? p.kind : 'computer';
    const os = OSES.includes(p.os) ? p.os : '', bg = p.bg === true;
    let peer = peers.get(p.id);
    if (!peer) { peer = { id: p.id, name, kind, os, bg, flash: null, hover: false }; peers.set(p.id, peer); buildCard(peer); changed = true; continue; }
    if (name !== peer.name) { peer.name = name; peer.nmEl.textContent = name; peer.hit.setAttribute('aria-label', 'send to ' + name); changed = true; }
    if (kind !== peer.kind || os !== peer.os) {
      if (kind !== peer.kind) { const ic = buildIcon(kind); peer.ic.pre.replaceWith(ic.pre); peer.ic = ic; }
      peer.kind = kind; peer.os = os; peer.tagEl.textContent = tagOf(peer);
    }
    if (bg !== peer.bg) { peer.bg = bg; peer.card.classList.toggle('away', bg); }
  }
  for (const [id, peer] of peers) {
    if (seen.has(id)) continue;
    peer.card.remove();
    peers.delete(id);
    if (composer && composer.target === id) composer.target = null;
    changed = true;
  }
  const t = Date.now();
  for (const c of conns.values()) {
    if (c.dead || (c.state !== 'asking' && c.state !== 'connecting')) continue;
    if (seen.has(c.peer)) c.goneAt = 0;
    else if (!c.goneAt) c.goneAt = t;
    else if (t - c.goneAt > 6000) fail(c, c.peerName + ' went offline', false);
  }
  if (changed) { paintDevices(); renderChips(); } else paintStatus();
}
function buildCard(peer) {
  peer.ic = buildIcon(peer.kind);
  peer.tagEl = h('span', { class: 'tag', text: tagOf(peer) });
  peer.nmEl = h('span', { class: 'nm', text: peer.name });
  peer.stEl = h('span', { class: 'st', id: 'st-' + peer.id, text: 'ready' });
  peer.hit = h('button', { class: 'hit', type: 'button', 'aria-label': 'send to ' + peer.name, 'aria-describedby': 'st-' + peer.id, onclick: () => sendTo(peer.id) },
    peer.tagEl, peer.ic.pre, peer.nmEl, peer.stEl);
  peer.card = h('div', {
    class: 'card' + (peer.bg ? ' away' : ''), 'data-id': peer.id,
    onmouseenter: () => { peer.hover = true; paintCards(); },
    onmouseleave: () => { peer.hover = false; paintCards(); },
  }, peer.hit, h('div', { class: 'card-acts' }, btn('', 'files', () => pickFor(peer.id)), btn('', 'note', () => openComposer(peer.id))));
  $('devs').append(peer.card);
}
function paintDevices() {
  const n = peers.size;
  txt($('devN'), n ? ' (' + n + ')' : '');
  $('devWrap').hidden = !n;
  $('empty').hidden = !!n;
  radar.set(!n);
  if (!n) paintEmpty();
  paintStatus();
  paintCards();
}
function paintCards() {
  const best = new Map();
  for (const c of conns.values()) {
    if (c.dead) continue;
    let v = null;
    if (c.state === 'transfer' || c.state === 'finishing') {
      const f = c.total ? bytesOf(c) / c.total : 1;
      v = { r: 3, mode: 'fill', frac: f, text: (c.role === 'send' ? 'sending ' : 'receiving ') + pct(f) };
    } else if (c.state === 'connecting') v = { r: 2, mode: 'spin', text: 'connecting…' };
    else if (c.state === 'asking') v = c.role === 'send' ? { r: 1, mode: 'wait', text: 'waiting for ok…' } : { r: 1, mode: 'ask', text: 'wants to send' };
    const cur = best.get(c.peer);
    if (v && (!cur || v.r > cur.r)) best.set(c.peer, v);
  }
  const armed = !!(staged || composer), wall = Date.now();
  for (const p of peers.values()) {
    let v = best.get(p.id), live = true;
    if (p.id === dragId) v = { mode: 'drop', text: 'drop to send' };
    else if (!v && p.flash && p.flash.until > wall) v = { mode: p.flash.ok ? 'ok' : 'bad', text: p.flash.text };
    else if (!v && armed) v = { mode: 'plus', text: TAP + ' to send' };
    else if (!v && p.hover && !TOUCH) v = { mode: 'plus', text: 'send files' };
    else if (!v) { live = false; v = { mode: 'idle', text: p.bg ? 'in background' : 'ready' }; }
    drawScreen(p.ic, v.mode, v.frac);
    txt(p.stEl, v.text);
    p.stEl.classList.toggle('live', live && v.mode !== 'bad');
    p.stEl.classList.toggle('err', v.mode === 'bad');
    p.card.classList.toggle('ready', armed);
  }
}

/* ---------- staging and notes ---------- */
const fkey = (f) => f.name + '|' + f.size + '|' + f.lastModified;
function stage(files) {
  files = Array.from(files || []).filter((f) => f instanceof File);
  if (!files.length) return;
  const list = staged ? staged.files : [], have = new Set(list.map(fkey));
  let skipped = 0;
  for (const f of files) {
    const k = fkey(f);
    if (have.has(k)) continue;
    if (list.length >= MAX_FILES) { skipped++; continue; }
    list.push(f);
    have.add(k);
  }
  if (skipped) toast('only ' + MAX_FILES + ' files at a time. zip the rest.', true);
  staged = { files: list };
  composer = null;
  paintDrop();
}
function unstage(f) {
  if (!staged) return;
  const i = staged.files.indexOf(f);
  if (i >= 0) staged.files.splice(i, 1);
  if (!staged.files.length) staged = null;
  paintDrop();
  const b = staged ? $('stagedList').querySelector('.rm') : $('chooseBtn');
  if (b) b.focus({ preventScroll: true });
}
function clearStaged() { staged = null; paintDrop(); }
function paintDrop() {
  const mode = composer ? 'note' : staged ? 'staged' : 'idle';
  $('dropIdle').hidden = mode !== 'idle';
  $('dropStaged').hidden = mode !== 'staged';
  $('dropNote').hidden = mode !== 'note';
  if (mode === 'staged') {
    const files = staged.files, total = files.reduce((a, f) => a + f.size, 0);
    $('stagedHead').textContent = plural(files.length, 'file') + ' · ' + fmtBytes(total);
    const rows = files.slice(0, 4).map((f) => h('li', {},
      h('span', { class: 'n', text: f.name, title: f.name }),
      h('span', { class: 'dim', text: fmtBytes(f.size) }),
      btn('rm', '×', () => unstage(f), { 'aria-label': 'remove ' + f.name })));
    if (files.length > 4) rows.push(h('li', { class: 'dim', text: '+ ' + (files.length - 4) + ' more' }));
    $('stagedList').replaceChildren(...rows);
  }
  renderChips();
  paintCards();
}
function renderChips() {
  const box = composer ? $('noteTo') : staged ? $('stagedTo') : null;
  if (!box) return;
  const list = [...peers.values()], tgt = composer && composer.target;
  if (tgt) list.sort((a, b) => (b.id === tgt) - (a.id === tgt));
  const kids = [h('span', { class: 'dim', text: list.length ? 'send to' : 'waiting for a device…' })];
  for (const p of list) kids.push(btn('chip' + (p.id === tgt || list.length === 1 ? ' pri' : ''), '→ ' + p.name, () => sendStagedTo(p.id)));
  if (list.length > 1) kids.push(btn('chip', '→ everyone', () => sendStagedTo('*')));
  box.replaceChildren(...kids);
}
function sendStagedTo(id) {
  const ids = id === '*' ? [...peers.keys()] : [id];
  if (composer) {
    const t = $('noteText').value;
    if (!t.trim()) { $('noteText').focus(); return toast('write something first'); }
    closeComposer(true);
    for (const x of ids) startSend(x, { text: cut(t, TEXT_MAX) });
  } else if (staged) {
    const s = staged;
    staged = null;
    paintDrop();
    for (const x of ids) startSend(x, s);
  } else pickFor(id);
}
function sendTo(id) { if (composer || staged) sendStagedTo(id); else pickFor(id); }
let pickTarget = null;
function pickFor(id) { pickTarget = id; const p = $('picker'); p.value = ''; p.click(); }
$('picker').addEventListener('change', () => {
  const files = Array.from($('picker').files || []), t = pickTarget;
  pickTarget = null;
  if (!files.length) return;
  if (t && peers.has(t)) return void startSend(t, { files });
  if (t) toast('that device left, so your files are staged instead');
  stage(files);
});
function openComposer(target, text) {
  composer = { target: target && peers.has(target) ? target : null };
  const ta = $('noteText');
  if (text != null) ta.value = cut(text, TEXT_MAX);
  paintDrop();
  ta.focus();
  try { ta.setSelectionRange(ta.value.length, ta.value.length); } catch {}
}
function closeComposer(clear) {
  if (!composer) return;
  composer = null;
  if (clear) $('noteText').value = '';
  paintDrop();
}
$('noteText').addEventListener('keydown', (e) => {
  if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) {
    e.preventDefault();
    const id = (composer && composer.target) || (peers.size === 1 ? peers.keys().next().value : null);
    if (id) sendStagedTo(id);
    else toast(peers.size ? 'pick a device under the text' : 'no devices yet');
  } else if (e.key === 'Escape') { e.preventDefault(); closeComposer(true); }
});

/* ---------- modals ---------- */
function openModal(id, focusEl) {
  if (!modals.includes(id)) { if (!modals.length) lastFocus = document.activeElement; modals.push(id); }
  $(id).hidden = false;
  $('app').setAttribute('inert', '');
  const f = focusEl || $(id).querySelector('button, input');
  if (f) f.focus({ preventScroll: true });
}
function closeModal(id) {
  const i = modals.indexOf(id);
  if (i < 0) return;
  modals.splice(i, 1);
  $(id).hidden = true;
  if (modals.length) { const f = $(modals[modals.length - 1]).querySelector('button, input'); if (f) f.focus(); return; }
  $('app').removeAttribute('inert');
  if (lastFocus && lastFocus.isConnected && lastFocus.focus) lastFocus.focus({ preventScroll: true });
  lastFocus = null;
}

/* ---------- incoming requests ---------- */
function showRequest(c) {
  asks.push(c);
  renderAsk();
  say(c.peerName + ' wants to send ' + c.label);
  try { if (navigator.vibrate) navigator.vibrate([60, 40, 60]); } catch {}
}
function dropRequest(c) { const i = asks.indexOf(c); if (i >= 0) { asks.splice(i, 1); renderAsk(); } }
function setAuto(v) { autoOn = v; $('askAuto').setAttribute('aria-pressed', String(v)); $('askBox').textContent = v ? '[x]' : '[ ]'; }
function renderAsk() {
  for (let i = asks.length - 1; i >= 0; i--) if (asks[i].dead || asks[i].state !== 'asking') asks.splice(i, 1);
  const c = asks[0];
  if (!c) { askCur = null; return closeModal('askOv'); }
  if (askCur !== c) {
    askCur = c;
    const ic = buildIcon((peers.get(c.peer) || {}).kind || 'computer');
    drawScreen(ic, 'q');
    $('askIc').replaceChildren(ic.pre);
    $('askT').textContent = c.peerName + ' wants to send you';
    $('askWhat').textContent = c.label;
    $('askSize').textContent = fmtBytes(c.total) + (c.count > 1 && !c.manifest.text ? ' · starts with ' + c.manifest.name : '');
    $('askAutoName').textContent = c.peerName;
    setAuto(false);
    closeModal('pairOv');
    openModal('askOv', $('askYes'));
  }
  txt($('askMore'), asks.length > 1 ? '+ ' + (asks.length - 1) + ' more waiting' : '');
  paintAskTimer();
}
function paintAskTimer() {
  const c = askCur;
  if (!c) return;
  const left = Math.max(0, c.askEnd - Date.now()), n = 24, k = Math.round(clamp01(left / (ASK_MS - 5000)) * n);
  txt($('askExp'), '[' + '#'.repeat(k) + '.'.repeat(n - k) + '] ' + Math.ceil(left / 1000) + 's');
}
function askAnswer(yes) {
  const c = askCur;
  if (!c) return;
  if (yes) { if (autoOn) autoAccept.add(c.peer); accept(c); } else decline(c);
}
$('askYes').addEventListener('click', () => askAnswer(true));
$('askNo').addEventListener('click', () => askAnswer(false));
$('askAuto').addEventListener('click', () => setAuto(!autoOn));

/* ---------- transfers ---------- */
function bytesOf(c) {
  if (c.role === 'recv') return c.done;
  if (c.state === 'finished' || c.state === 'finishing') return c.total;
  return c.ch && c.state === 'transfer' ? Math.max(0, c.sent - c.ch.bufferedAmount) : 0;
}
function paint(c) {
  if (!c.ui) {
    if ((c.role === 'recv' && c.state === 'asking') || (c.state === 'failed' && !c.error)) return;
    const u = (c.ui = {});
    u.what = h('span', { class: 'tx-what' });
    u.retry = btn('tx-b', 'retry', () => retry(c));
    u.x = btn('tx-b', 'cancel', () => (c.dead ? removeTx(c) : fail(c, 'cancelled')));
    u.sub = h('div', { class: 'tx-2' });
    u.fill = h('i');
    u.rest = h('span');
    u.pc = h('span');
    u.prog = h('div', { class: 'tx-3' }, h('span', { 'aria-hidden': 'true' }, '[', u.fill, u.rest, '] '), u.pc);
    u.li = h('li', { class: 'tx' },
      h('div', { class: 'tx-1' }, h('span', { class: 'dim', 'aria-hidden': 'true', text: c.role === 'send' ? '↑' : '↓' }), u.what, u.retry, u.x),
      u.sub, u.prog);
    $('txs').append(u.li);
    paintAct();
  }
  const u = c.ui, b = bytesOf(c), f = c.total ? b / c.total : c.state === 'finished' ? 1 : 0;
  const moving = c.state === 'transfer' || c.state === 'finishing';
  const who = (c.role === 'send' ? 'to ' : 'from ') + c.peerName;
  txt(u.what, c.label + (c.count > 1 && c.state === 'transfer' && c.file ? ' · ' + c.file : ''));
  txt(u.x, c.dead ? 'dismiss' : 'cancel');
  u.retry.hidden = !(c.state === 'failed' && c.role === 'send' && c.what && c.error !== 'cancelled');
  u.li.classList.toggle('bad', c.state === 'failed');
  txt(u.sub,
    c.state === 'asking' ? (c.role === 'send' ? 'waiting for ' + c.peerName + ' to accept…' : who)
    : c.state === 'connecting' ? who + ' · connecting…'
    : c.state === 'transfer' ? who + ' · ' + fmtBytes(b) + ' / ' + fmtBytes(c.total) + (c.rate > 0 ? ' · ' + fmtBytes(c.rate) + '/s · ' + fmtTime((c.total - b) / c.rate) + ' left' : '')
    : c.state === 'finishing' ? who + ' · finishing…'
    : c.state === 'finished' ? who + ' · ' + fmtBytes(c.total) + ' in ' + fmtTime((c.endAt - c.t0) / 1000)
    : c.error || who);
  u.prog.hidden = !moving;
  if (moving) {
    const n = 16, k = Math.round(clamp01(f) * n);
    txt(u.fill, '#'.repeat(k));
    txt(u.rest, '.'.repeat(n - k));
    txt(u.pc, pct(f));
  }
}
function retry(c) {
  if (!c.what) return;
  if (!peers.has(c.peer)) return toast(c.peerName + ' is no longer here', true);
  removeTx(c);
  startSend(c.peer, c.what);
}
function removeTx(c) { const u = c.ui; if (!u) return; c.ui = null; u.li.remove(); paintAct(); }
function retire(c, ms) {
  setTimeout(() => {
    const u = c.ui;
    if (!u) return;
    u.li.classList.add('gone');
    setTimeout(() => { if (c.ui === u) removeTx(c); }, 450);
  }, ms);
}
let actShut = false;
function setShut(v) {
  actShut = v;
  $('act').classList.toggle('shut', v);
  $('actT').setAttribute('aria-expanded', String(!v));
  $('actSign').textContent = v ? '[+]' : '[-]';
}
function paintAct() {
  const nt = $('txs').children.length, nr = received.length, any = nt + nr > 0;
  $('act').hidden = !any;
  if (!any && actShut) setShut(false);
  $('actTools').hidden = !nr;
}
$('actT').addEventListener('click', () => setShut(!actShut));

/* ---------- received ---------- */
const urlOf = (it) => it.url || (it.url = URL.createObjectURL(it.blob));
const fileOf = (it) => it.file || (it.file = new File([it.blob], it.name, { type: it.blob.type }));
function save(it) { const a = h('a', { href: urlOf(it), download: it.name }); document.body.append(a); a.click(); a.remove(); }
function canShare(it) { try { return !!(navigator.share && navigator.canShare && navigator.canShare({ files: [fileOf(it)] })); } catch { return false; } }
async function shareItem(it) {
  try { await navigator.share({ files: [fileOf(it)] }); } catch (e) { if (!e || e.name !== 'AbortError') toast("couldn't share this file", true); }
}
function addReceived(it) {
  received.push(it);
  it.agoEl = h('span', { text: ago(it.t) });
  let li;
  if (it.text != null) {
    const url = /^https?:\/\/\S+$/i.test(it.text.trim()) ? it.text.trim() : '';
    li = h('li', { class: 'nt' },
      h('div', { class: 'rx-l2' },
        h('span', { class: 'rx-m' }, 'note from ', h('span', { class: 'b', text: it.from }), ' · ', it.agoEl),
        h('span', { class: 'rx-a' },
          btn('lnk hi', 'copy', (e) => copyText(it.text, e.currentTarget)),
          url ? ' · ' : null,
          url ? h('a', { class: 'lnk', href: url, target: '_blank', rel: 'noopener noreferrer', text: 'open' }) : null)),
      h('pre', { class: 'note scroll', text: it.text }));
  } else {
    const img = /^image\/(png|jpeg|gif|webp|avif|bmp)$/.test(it.mime) && it.size < (25 << 20);
    const sh = canShare(it);
    li = h('li', {},
      img ? h('img', { class: 'thumb', src: urlOf(it), alt: '', decoding: 'async' }) : h('span', { class: 'thumb ph', 'aria-hidden': 'true', text: extOf(it.name) }),
      h('div', { class: 'rx-main' },
        h('div', { class: 'rx-n', text: it.name, title: it.name }),
        h('div', { class: 'rx-l2' },
          h('span', { class: 'rx-m' }, fmtBytes(it.size) + ' · ' + it.from + ' · ', it.agoEl),
          h('span', { class: 'rx-a' },
            h('a', { class: 'lnk hi', href: urlOf(it), download: it.name, text: 'save' }),
            sh ? ' · ' : null,
            sh ? btn('lnk', 'share', () => shareItem(it)) : null))));
  }
  $('rxs').prepend(li);
  paintAct();
}
async function copyText(text, b) {
  const label = b.dataset.label || (b.dataset.label = b.textContent);
  let ok = false;
  try { await navigator.clipboard.writeText(text); ok = true; } catch {
    const ta = h('textarea', { class: 'sr', readonly: true });
    ta.value = text;
    document.body.append(ta);
    ta.select();
    try { ok = document.execCommand('copy'); } catch {}
    ta.remove();
  }
  b.textContent = ok ? 'copied' : 'copy failed';
  setTimeout(() => { b.textContent = label; }, 1500);
}
$('rxSaveAll').addEventListener('click', () => { received.filter((it) => it.text == null).forEach((it, i) => setTimeout(() => save(it), i * 300)); });
$('rxClear').addEventListener('click', () => {
  for (const it of received) if (it.url) URL.revokeObjectURL(it.url);
  received.length = 0;
  $('rxs').replaceChildren();
  paintAct();
});

/* ---------- this device ---------- */
function paintMe() { $('meName').textContent = me.name; $('meSub').textContent = tagOf(me); }
function paintSave() { $('saveBtn').setAttribute('aria-checked', String(autoSave)); $('saveBox').textContent = autoSave ? '[x]' : '[ ]'; }
$('saveBtn').addEventListener('click', () => {
  autoSave = !autoSave;
  store.set('autosave', autoSave ? '1' : '0');
  paintSave();
  toast(autoSave ? 'incoming files will download automatically' : 'incoming files will wait in activity until you save them');
});
$('renameBtn').addEventListener('click', () => {
  $('meRow').hidden = true;
  $('renameForm').hidden = false;
  const i = $('renameIn');
  i.value = me.name;
  i.focus();
  i.select();
});
function endRename(keepIt) {
  if ($('renameForm').hidden) return;
  if (keepIt) {
    const n = cleanName($('renameIn').value);
    if (n && n !== me.name) { me.name = n; store.set('name', n); paintMe(); pollNow(); }
  }
  $('renameForm').hidden = true;
  $('meRow').hidden = false;
  $('renameBtn').focus();
}
$('renameForm').addEventListener('submit', (e) => { e.preventDefault(); endRename(true); });
$('renameCancel').addEventListener('click', () => endRename(false));
$('renameIn').addEventListener('keydown', (e) => { if (e.key === 'Escape') { e.preventDefault(); endRename(false); } });

/* ---------- rooms and pairing ---------- */
const shareUrl = () => location.origin + location.pathname + (room ? '#' + room : '');
function leave() {
  const body = JSON.stringify({ a: 'leave', s: me.secret, room });
  let ok = false;
  try { ok = navigator.sendBeacon(API, body); } catch {}
  if (!ok) fetch(API, { method: 'POST', body, keepalive: true }).catch(() => {});
}
function setRoom(code) {
  if (code === room) return;
  leave();
  // Handshakes can't follow us; transfers already flowing are direct and keep going.
  for (const c of conns.values()) if (!c.dead && (c.state === 'asking' || c.state === 'connecting')) fail(c, 'switched rooms');
  room = code;
  history.replaceState(null, '', code ? '#' + code : location.pathname + location.search);
  for (const p of peers.values()) p.card.remove();
  peers.clear();
  if (composer) composer.target = null;
  emptyKey = null;
  paintDevices();
  renderChips();
  if (modals.includes('pairOv')) { renderPair(); $('pairCopy').focus(); }
  pollNow();
}
addEventListener('hashchange', () => { const r = hashRoom(); if (r !== room) setRoom(r); });
function renderPair() {
  const url = shareUrl(), svg = qrSvg(url);
  $('pairQr').replaceChildren(...(svg ? [svg] : []));
  $('pairQr').hidden = !svg;
  $('pairUrl').textContent = url;
  $('pairShare').hidden = !navigator.share;
  $('pairRoom').replaceChildren(
    h('p', {}, h('span', { class: 'dim', text: 'room · ' }), h('span', { class: 'b', text: room ? pretty(room) : 'this network' })),
    h('p', { class: 'dim sm', text: room
      ? 'private: only devices using this code see each other, on any network.'
      : "devices reaching this site from the same internet connection see each other. if one doesn't show up, use a private code." }),
    h('div', { class: 'acts' }, ...(room
      ? [btn('btn sm', 'new code', () => setRoom(newCode())), btn('btn sm', 'back to this network', () => setRoom(''))]
      : [btn('btn sm', 'use a private code', () => setRoom(newCode()))])));
}
function openPair() { renderPair(); openModal('pairOv', $('pairCopy')); }
$('pairBtn').addEventListener('click', openPair);
$('pairX').addEventListener('click', () => closeModal('pairOv'));
$('pairOv').addEventListener('click', (e) => { if (e.target === e.currentTarget) closeModal('pairOv'); });
$('pairCopy').addEventListener('click', (e) => copyText(shareUrl(), e.currentTarget));
$('pairShare').addEventListener('click', () => { navigator.share({ title: 'localdrop', url: shareUrl() }).catch(() => {}); });
$('joinForm').addEventListener('submit', (e) => {
  e.preventDefault();
  const i = $('joinIn'), v = normCode(i.value);
  if (!validCode(v)) { i.classList.add('bad'); i.focus(); return toast('codes are 6 to 32 letters or digits', true); }
  i.value = '';
  i.classList.remove('bad');
  setRoom(v);
  toast('joined room ' + pretty(v));
});

let emptyKey = null;
function paintEmpty() {
  const url = shareUrl();
  if (url === emptyKey) return;
  emptyKey = url;
  const svg = qrSvg(url);
  $('emptyT').replaceChildren(
    h('p', { class: 'b' }, 'looking for devices', h('span', { class: 'cur', 'aria-hidden': 'true', text: '_' })),
    room
      ? h('p', {}, 'this device is in room ', h('span', { class: 'b', text: pretty(room) }), '. open the same link on your other device, or enter the code there.')
      : h('p', { text: 'open this page on your other device, connected to the same wi-fi.' }),
    svg ? h('div', { class: 'qr-row' }, svg, h('p', { class: 'dim sm', text: "or point your phone's camera at this code." })) : null,
    h('div', { class: 'show-sm-b' }, btn('btn sm', 'show link & qr code', openPair)),
    room
      ? h('p', { class: 'dim sm' }, "can't scan? ", btn('lnk', 'copy the link', (e) => copyText(shareUrl(), e.currentTarget)))
      : h('p', { class: 'dim sm' }, 'not showing up? some networks split devices up. ', btn('lnk', 'use a private code', () => setRoom(newCode())), ' instead.'));
}

/* ---------- ascii radar ---------- */
const radar = (() => {
  const R = 6, W = R * 4 + 1, H = R * 2 + 1, TAU = Math.PI * 2, cells = [];
  for (let y = 0; y < H; y++) for (let x = 0; x < W; x++) {
    const dx = (x - R * 2) / 2, dy = y - R, d = Math.hypot(dx, dy);
    cells.push({ d, a: Math.atan2(dy, dx), base: d < 0.5 ? '@' : Math.abs(d - R) < 0.45 || Math.abs(d - R / 2) < 0.3 ? '.' : ' ', eol: x === W - 1 });
  }
  const still = matchMedia('(prefers-reduced-motion: reduce)');
  let ang = 0.9, iv = 0, on = false;
  function draw() {
    let lo = '', hi = '';
    for (const c of cells) {
      let l = c.base, u = ' ';
      if (c.d >= 0.5 && c.d <= R + 0.3) {
        let df = (ang - c.a) % TAU;
        if (df < 0) df += TAU;
        if (df < 0.2) { u = '#'; l = ' '; }
        else if (df < 0.45) { u = '+'; l = ' '; }
        else if (df < 0.85) l = '-';
        else if (df < 1.35 && l === ' ') l = '.';
      }
      lo += l;
      hi += u;
      if (c.eol) { lo += '\n'; hi += '\n'; }
    }
    $('radLo').textContent = lo;
    $('radHi').textContent = hi;
  }
  function sync() {
    const run = on && !document.hidden && !still.matches;
    if (run && !iv) iv = setInterval(() => { ang = (ang + 0.13) % TAU; draw(); }, 70);
    else if (!run && iv) { clearInterval(iv); iv = 0; }
  }
  return { set(v) { if (v && !on) draw(); on = v; sync(); }, sync };
})();

/* ---------- qr code (byte mode, versions 1-10, ecc M then L) ---------- */
const qrSvg = (() => {
  const TAB = {
    M: [[10, 1], [16, 1], [26, 1], [18, 2], [24, 2], [16, 4], [18, 4], [22, 4], [22, 5], [26, 5]],
    L: [[7, 1], [10, 1], [15, 1], [20, 1], [26, 1], [18, 2], [20, 2], [24, 2], [30, 2], [18, 4]],
  };
  const FMT = { M: 0, L: 1 };
  const mul = (x, y) => { let z = 0; for (let i = 7; i >= 0; i--) { z = (z << 1) ^ ((z >>> 7) * 0x11d); z ^= ((y >>> i) & 1) * x; } return z; };
  const raw = (v) => { let r = (16 * v + 128) * v + 64; if (v >= 2) { const a = Math.floor(v / 7) + 2; r -= (25 * a - 10) * a - 55; if (v >= 7) r -= 36; } return r; };
  const align = (v) => {
    if (v === 1) return [];
    const a = Math.floor(v / 7) + 2, step = Math.ceil((v * 4 + 4) / (a * 2 - 2)) * 2, out = [6];
    for (let p = v * 4 + 10; out.length < a; p -= step) out.splice(1, 0, p);
    return out;
  };
  function rsDiv(deg) {
    const r = new Array(deg).fill(0);
    r[deg - 1] = 1;
    let root = 1;
    for (let i = 0; i < deg; i++) {
      for (let j = 0; j < deg; j++) { r[j] = mul(r[j], root); if (j + 1 < deg) r[j] ^= r[j + 1]; }
      root = mul(root, 2);
    }
    return r;
  }
  function rsRem(data, div) {
    const r = div.map(() => 0);
    for (const b of data) { const f = b ^ r.shift(); r.push(0); div.forEach((c, i) => { r[i] ^= mul(c, f); }); }
    return r;
  }
  function maskOn(k, x, y) {
    switch (k) {
      case 0: return (x + y) % 2 === 0;
      case 1: return y % 2 === 0;
      case 2: return x % 3 === 0;
      case 3: return (x + y) % 3 === 0;
      case 4: return (Math.floor(x / 3) + Math.floor(y / 2)) % 2 === 0;
      case 5: return ((x * y) % 2) + ((x * y) % 3) === 0;
      case 6: return (((x * y) % 2) + ((x * y) % 3)) % 2 === 0;
      default: return (((x + y) % 2) + ((x * y) % 3)) % 2 === 0;
    }
  }
  function penalty(g, n) {
    let p = 0, dark = 0;
    for (let pass = 0; pass < 2; pass++) for (let a = 0; a < n; a++) {
      let run = 0, prev = null, line = '';
      for (let b = 0; b < n; b++) {
        const v = pass ? g[b][a] : g[a][b];
        line += v ? '1' : '0';
        if (v === prev) { run++; if (run === 5) p += 3; else if (run > 5) p++; } else { run = 1; prev = v; }
      }
      const s = '0000' + line + '0000';
      for (const pat of ['00001011101', '10111010000']) for (let i = s.indexOf(pat); i >= 0; i = s.indexOf(pat, i + 1)) p += 40;
    }
    for (let y = 0; y < n - 1; y++) for (let x = 0; x < n - 1; x++) {
      const v = g[y][x];
      if (v === g[y][x + 1] && v === g[y + 1][x] && v === g[y + 1][x + 1]) p += 3;
    }
    for (const row of g) for (const v of row) if (v) dark++;
    return p + Math.max(0, Math.ceil(Math.abs(dark * 20 - n * n * 10) / (n * n)) - 1) * 10;
  }
  function draw(v, lvl, cw) {
    const n = v * 4 + 17;
    const g = Array.from({ length: n }, () => new Array(n).fill(false));
    const fn = Array.from({ length: n }, () => new Array(n).fill(false));
    const set = (x, y, d) => { g[y][x] = d; fn[y][x] = true; };
    for (let i = 0; i < n; i++) { set(6, i, i % 2 === 0); set(i, 6, i % 2 === 0); }
    for (const [cx, cy] of [[3, 3], [n - 4, 3], [3, n - 4]]) {
      for (let dy = -4; dy <= 4; dy++) for (let dx = -4; dx <= 4; dx++) {
        const x = cx + dx, y = cy + dy, d = Math.max(Math.abs(dx), Math.abs(dy));
        if (x >= 0 && x < n && y >= 0 && y < n) set(x, y, d !== 2 && d !== 4);
      }
    }
    const ap = align(v), na = ap.length;
    for (let i = 0; i < na; i++) for (let j = 0; j < na; j++) {
      if ((i === 0 && j === 0) || (i === 0 && j === na - 1) || (i === na - 1 && j === 0)) continue;
      for (let dy = -2; dy <= 2; dy++) for (let dx = -2; dx <= 2; dx++) set(ap[i] + dx, ap[j] + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1);
    }
    const fmt = (grid, mask) => {
      const d = (FMT[lvl] << 3) | mask;
      let r = d;
      for (let i = 0; i < 10; i++) r = (r << 1) ^ ((r >>> 9) * 0x537);
      const b = ((d << 10) | r) ^ 0x5412, bit = (i) => ((b >>> i) & 1) === 1;
      const s = (x, y, val) => { grid[y][x] = val; fn[y][x] = true; };
      for (let i = 0; i <= 5; i++) s(8, i, bit(i));
      s(8, 7, bit(6)); s(8, 8, bit(7)); s(7, 8, bit(8));
      for (let i = 9; i < 15; i++) s(14 - i, 8, bit(i));
      for (let i = 0; i < 8; i++) s(n - 1 - i, 8, bit(i));
      for (let i = 8; i < 15; i++) s(8, n - 15 + i, bit(i));
      s(8, n - 8, true);
    };
    fmt(g, 0);
    if (v >= 7) {
      let r = v;
      for (let i = 0; i < 12; i++) r = (r << 1) ^ ((r >>> 11) * 0x1f25);
      const b = (v << 12) | r;
      for (let i = 0; i < 18; i++) { const d = ((b >>> i) & 1) === 1, a = n - 11 + (i % 3), c = Math.floor(i / 3); set(a, c, d); set(c, a, d); }
    }
    let i = 0;
    for (let right = n - 1; right >= 1; right -= 2) {
      if (right === 6) right = 5;
      for (let vert = 0; vert < n; vert++) for (let j = 0; j < 2; j++) {
        const x = right - j, y = ((right + 1) & 2) === 0 ? n - 1 - vert : vert;
        if (!fn[y][x] && i < cw.length * 8) { g[y][x] = ((cw[i >>> 3] >>> (7 - (i & 7))) & 1) === 1; i++; }
      }
    }
    let best = null, bestP = Infinity;
    for (let k = 0; k < 8; k++) {
      const t = g.map((row) => row.slice());
      for (let y = 0; y < n; y++) for (let x = 0; x < n; x++) if (!fn[y][x] && maskOn(k, x, y)) t[y][x] = !t[y][x];
      fmt(t, k);
      const p = penalty(t, n);
      if (p < bestP) { bestP = p; best = t; }
    }
    return best;
  }
  function encode(text) {
    const bytes = new TextEncoder().encode(text);
    for (const lvl of ['M', 'L']) for (let v = 1; v <= 10; v++) {
      const [ecLen, nb] = TAB[lvl][v - 1], total = Math.floor(raw(v) / 8), cap = (total - ecLen * nb) * 8, cc = v < 10 ? 8 : 16;
      if (4 + cc + bytes.length * 8 > cap) continue;
      const bits = [];
      const put = (val, len) => { for (let i = len - 1; i >= 0; i--) bits.push((val >>> i) & 1); };
      put(4, 4);
      put(bytes.length, cc);
      for (const b of bytes) put(b, 8);
      put(0, Math.min(4, cap - bits.length));
      put(0, (8 - (bits.length % 8)) % 8);
      for (let pad = 0xec; bits.length < cap; pad ^= 0xec ^ 0x11) put(pad, 8);
      const data = [];
      for (let i = 0; i < bits.length; i += 8) { let x = 0; for (let j = 0; j < 8; j++) x = (x << 1) | bits[i + j]; data.push(x); }
      const nShort = nb - (total % nb), shortLen = Math.floor(total / nb), div = rsDiv(ecLen), blocks = [];
      for (let i = 0, k = 0; i < nb; i++) {
        const dat = data.slice(k, k + shortLen - ecLen + (i < nShort ? 0 : 1));
        k += dat.length;
        const ecc = rsRem(dat, div);
        if (i < nShort) dat.push(0);
        blocks.push(dat.concat(ecc));
      }
      const cw = [];
      for (let i = 0; i < blocks[0].length; i++) blocks.forEach((b, j) => { if (i !== shortLen - ecLen || j >= nShort) cw.push(b[i]); });
      return draw(v, lvl, cw);
    }
    return null;
  }
  const cache = new Map();
  return (text) => {
    let m = cache.get(text);
    if (m === undefined) { try { m = encode(text); } catch { m = null; } cache.set(text, m); }
    if (!m) return null;
    const n = m.length, q = 4, s = n + q * 2, NS = 'http://www.w3.org/2000/svg';
    let d = '';
    for (let y = 0; y < n; y++) for (let x = 0; x < n; x++) if (m[y][x]) d += 'M' + (x + q) + ' ' + (y + q) + 'h1v1h-1z';
    const svg = document.createElementNS(NS, 'svg'), bg = document.createElementNS(NS, 'rect'), path = document.createElementNS(NS, 'path');
    svg.setAttribute('viewBox', '0 0 ' + s + ' ' + s);
    svg.setAttribute('class', 'qr');
    svg.setAttribute('role', 'img');
    svg.setAttribute('aria-label', 'qr code for ' + text);
    svg.setAttribute('shape-rendering', 'crispEdges');
    bg.setAttribute('width', s);
    bg.setAttribute('height', s);
    bg.setAttribute('fill', '#fff');
    path.setAttribute('d', d);
    path.setAttribute('fill', '#000');
    svg.append(bg, path);
    return svg;
  };
})();

/* ---------- drop, paste, keys ---------- */
let dragT = 0;
const hasFiles = (e) => !!e.dataTransfer && Array.from(e.dataTransfer.types || []).includes('Files');
const cardAt = (e) => (e.target && e.target.closest ? e.target.closest('.card') : null);
const typing = (e) => !!(e.target && e.target.closest && e.target.closest('input, textarea'));
function setDrag(id, on) {
  $('veil').hidden = !on;
  $('drop').classList.toggle('hot', on);
  for (const p of peers.values()) p.card.classList.toggle('over', on && p.id === id);
  if (dragId !== id) { dragId = id; paintCards(); }
}
document.addEventListener('dragover', (e) => {
  if (!hasFiles(e)) return;
  e.preventDefault(); // never let the browser open a dropped file in place of the page
  if (modals.length) { e.dataTransfer.dropEffect = 'none'; return; }
  e.dataTransfer.dropEffect = 'copy';
  const card = cardAt(e);
  setDrag(card ? card.dataset.id : null, true);
  clearTimeout(dragT);
  dragT = setTimeout(() => setDrag(null, false), 200);
});
document.addEventListener('drop', (e) => {
  if (!hasFiles(e)) return;
  e.preventDefault();
  if (modals.length) return;
  const card = cardAt(e);
  clearTimeout(dragT);
  setDrag(null, false);
  const files = [];
  let folders = 0;
  for (const it of Array.from(e.dataTransfer.items || [])) {
    if (it.kind !== 'file') continue;
    const en = it.webkitGetAsEntry ? it.webkitGetAsEntry() : null;
    if (en && en.isDirectory) { folders++; continue; }
    const f = it.getAsFile();
    if (f) files.push(f);
  }
  if (!files.length && !folders) files.push(...Array.from(e.dataTransfer.files || []));
  if (folders) toast("folders can't be sent as they are. zip them first.", true);
  if (!files.length) return;
  if (card && peers.has(card.dataset.id)) startSend(card.dataset.id, { files });
  else stage(files);
});
document.addEventListener('paste', (e) => {
  if (typing(e) || !e.clipboardData || modals.length) return;
  const files = Array.from(e.clipboardData.files || []);
  if (files.length) { e.preventDefault(); return stage(files); }
  const text = e.clipboardData.getData('text/plain');
  if (!text || !text.trim()) return;
  e.preventDefault();
  if (composer) { const ta = $('noteText'); ta.value = cut(ta.value + text, TEXT_MAX); ta.focus(); }
  else openComposer(null, text);
});
document.addEventListener('keydown', (e) => {
  if (e.ctrlKey || e.metaKey || e.altKey) return;
  const k = e.key, top = modals[modals.length - 1];
  if (top === 'askOv') {
    if (k === 'y' || k === 'Y') { e.preventDefault(); askAnswer(true); }
    else if (k === 'n' || k === 'N' || k === 'Escape') { e.preventDefault(); askAnswer(false); }
    return;
  }
  if (top) { if (k === 'Escape') { e.preventDefault(); closeModal(top); } return; }
  if (typing(e)) return;
  if (k === 'Escape') { if (composer) closeComposer(true); else if (staged) clearStaged(); return; }
  if (e.repeat) return;
  if (k === 'f') { e.preventDefault(); pickFor(null); }
  else if (k === 't') { e.preventDefault(); openComposer(null); }
  else if (k === 'c') { e.preventDefault(); openPair(); }
});
$('chooseBtn').addEventListener('click', () => pickFor(null));
$('noteBtn').addEventListener('click', () => openComposer(null));
$('stagedAdd').addEventListener('click', () => pickFor(null));
$('stagedClear').addEventListener('click', clearStaged);
$('noteCancel').addEventListener('click', () => closeComposer(true));

/* ---------- ui tick: speeds, screens, timers, title ---------- */
setInterval(() => {
  ticks++;
  const t = now();
  let n = 0, sum = 0, tot = 0;
  for (const c of conns.values()) {
    if (c.dead) continue;
    if (c.state === 'transfer' || c.state === 'finishing') {
      const b = bytesOf(c);
      if (c.mark && t - c.mark.t >= 1000) {
        const r = (b - c.mark.b) * 1000 / (t - c.mark.t);
        c.rate = c.rate ? c.rate * 0.6 + r * 0.4 : r;
        c.mark = { t, b };
      }
      n++; sum += b; tot += c.total;
    }
    paint(c);
  }
  paintCards();
  paintAskTimer();
  if (ticks % 40 === 0) for (const it of received) if (it.agoEl) txt(it.agoEl, ago(it.t));
  const title = (asks.length ? '(' + asks.length + ') ' : n ? pct(tot ? sum / tot : 1) + ' · ' : '') + 'localdrop';
  if (document.title !== title) document.title = title;
}, 250);

/* ---------- lifecycle ---------- */
document.addEventListener('visibilitychange', () => { radar.sync(); pollNow(); if (!document.hidden && active().length) wake.hold(); });
addEventListener('pageshow', (e) => { if (e.persisted) pollNow(); });
addEventListener('online', () => { fails = 0; pollNow(); });
addEventListener('beforeunload', (e) => { if (active().length) { e.preventDefault(); e.returnValue = ''; } });
addEventListener('pagehide', leave);

const meIc = buildIcon(me.kind);
drawScreen(meIc, 'you');
$('meIc').append(meIc.pre);
document.querySelectorAll('.mod').forEach((e) => { e.textContent = MOD; });
paintMe();
paintSave();
paintDrop();
paintDevices();
paintAct();
if (!window.RTCPeerConnection) {
  setOnline(false, "this browser can't make direct connections");
  toast("this browser can't send or receive files. try a recent chrome, firefox or safari.", true);
  return;
}
poll();
})();
</script>
</body>
</html>
