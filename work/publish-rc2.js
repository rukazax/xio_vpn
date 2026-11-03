const fs = require('fs');
const path = require('path');
const https = require('https');

const TOKEN = JSON.parse(fs.readFileSync(process.env.USERPROFILE + '/.dsh/secrets/github.json', 'utf8')).token;
const OWNER = 'rukazax', REPO = 'xio_vpn';
const TAG = 'v0.24.1-rc2';
const TARGET = process.env.XIO_TARGET_COMMIT || 'release-0.24.0';
const RELEASES = 'C:/Users/er-ka/Documents/deepseek-harness/xio_vpn/work/repo-edit/releases';
const ASSETS = [
  'XIO-Full-0.24.1-windows-x64.zip',
  'XIO-0.24.1-ubuntu-amd64.deb',
  'XIO-0.24.1-ubuntu-x64.tar.gz',
  'xio-server-0.24.1.tar.gz',
  'SHA256SUMS-0.24.1.txt',
];

const sums = fs.readFileSync(path.join(RELEASES, 'SHA256SUMS-0.24.1.txt'), 'utf8').trim();

const BODY = `**Предрелиз 0.24.1 (rc2).** Собран из коммита \`${TARGET}\` ветки \`release-0.24.0\`.

RU: 0.24.1 исправляет серверный пакет 0.24.0, который не устанавливался (в архиве не было \`readiness.py\` и \`xio-ready.service\`), и добавляет три вещи. Первое — каталог «белых» SNI: генератор, pin источника, недельный таймер, lint и чтение пригодных имён администратором; каталог не маршрутизирует по домену и не применяет маску сам. Второе — статичный AmneziaWG для устройств без клиента XIO (роутеры, iPhone с AmneziaVPN): действие \`add-awg\` в admin.py и утилита \`xio-peer.py\` с QR-кодом, профиль с MTU 1232 по замеру PMTU. Третье — каскад «IPv4-вход → IPv6-выход»: bridge принимает клиентов любым транспортом, IPv6-трафик уходит на IPv6-сервер через SSH-туннель L3 поверх IPv4-прокси провайдера; проверено живым подключением телефона (IPv4 27 мс, IPv6 115–150 мс). Серверный архив теперь 27 членов: 21 базовый + 6 \`catalog/\`, плюс \`xio-peer.py\` и файлы роли каскада. Версия приложения 0.24.1+5018. Десктопные бандлы пересобраны из этого же коммита.

EN: 0.24.1 fixes the 0.24.0 server package (it shipped without \`readiness.py\` and \`xio-ready.service\`) and adds three things. First, the white-SNI catalog: builder, source pin, weekly timer, lint, and an administrator action that lists eligible names; the catalog does not route by domain and never applies a mask on its own. Second, static AmneziaWG for devices without the XIO client (routers, iPhones with AmneziaVPN): the \`add-awg\` admin action and the \`xio-peer.py\` utility with a QR code, profile MTU 1232 from the measured PMTU. Third, the "IPv4 entry → IPv6 exit" cascade: the bridge accepts clients on any transport and sends IPv6 traffic to the IPv6 server through an SSH L3 tunnel over the provider IPv4 proxy; verified by a live phone connection (IPv4 27 ms, IPv6 115–150 ms). The server archive now has 27 members: 21 base + 6 \`catalog/\`, plus \`xio-peer.py\` and the cascade role files. App version 0.24.1+5018. Desktop bundles are rebuilt from the same commit.

**SHA-256**
\`\`\`
${sums}
\`\`\`
`;

function api(method, route, body) {
  return new Promise((resolve, reject) => {
    const data = body ? JSON.stringify(body) : null;
    const req = https.request({
      hostname: 'api.github.com', path: route, method,
      headers: {
        Authorization: 'Bearer ' + TOKEN, Accept: 'application/vnd.github+json',
        'User-Agent': 'xio-release-script',
        ...(data ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) } : {}),
      },
    }, (res) => {
      let chunks = '';
      res.on('data', (c) => (chunks += c));
      res.on('end', () => {
        let parsed = null;
        try { parsed = chunks ? JSON.parse(chunks) : null; } catch { parsed = chunks; }
        if (res.statusCode >= 300) reject(new Error(`${method} ${route} -> ${res.statusCode}: ${chunks.slice(0, 400)}`));
        else resolve(parsed);
      });
    });
    req.on('error', reject);
    if (data) req.write(data);
    req.end();
  });
}

function upload(uploadUrl, file) {
  const buffer = fs.readFileSync(file);
  const name = path.basename(file);
  const url = new URL(uploadUrl.replace('{?name,label}', '?name=' + encodeURIComponent(name)));
  return new Promise((resolve, reject) => {
    const req = https.request({
      hostname: url.hostname, path: url.pathname + url.search, method: 'POST',
      headers: {
        Authorization: 'Bearer ' + TOKEN, Accept: 'application/vnd.github+json',
        'User-Agent': 'xio-release-script', 'Content-Type': 'application/octet-stream',
        'Content-Length': buffer.length,
      },
    }, (res) => {
      let chunks = '';
      res.on('data', (c) => (chunks += c));
      res.on('end', () => res.statusCode >= 300
        ? reject(new Error(`upload ${name} -> ${res.statusCode}: ${chunks.slice(0, 200)}`))
        : resolve(name));
    });
    req.on('error', reject);
    req.write(buffer);
    req.end();
  });
}

(async () => {
  let release;
  try {
    release = await api('POST', `/repos/${OWNER}/${REPO}/releases`, {
      tag_name: TAG, target_commitish: TARGET, name: 'XIO 0.24.1 (pre-release, rc2)',
      body: BODY, prerelease: true, draft: false,
    });
  } catch (error) {
    if (!String(error.message).includes('422')) throw error;
    release = await api('GET', `/repos/${OWNER}/${REPO}/releases/tags/${TAG}`);
    console.log('release exists, reusing');
  }
  console.log('release:', release.html_url);
  for (const asset of ASSETS) console.log('uploaded', await upload(release.upload_url, path.join(RELEASES, asset)));
})().catch((error) => { console.error('FAILED', error.message); process.exit(1); });
