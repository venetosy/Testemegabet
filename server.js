// Mega Bet — servidor de pagamentos (Laranjinha PIX).
// A chave secreta (sk_live_...) fica SÓ aqui, em variável de ambiente. Nunca coloque no HTML/JS do app.
//
// Variáveis de ambiente:
//   BOT_TOKEN       token do bot do Telegram (valida o login de quem abre o app)
//   PAY_KEY         chave secreta da Laranjinha (sk_live_...)
//   WEBHOOK_SECRET  segredo de assinatura do webhook (mostrado no painel da Laranjinha ao criar o webhook)
//   ORIGIN          endereço do seu site, ex.: https://seusite.com  (libera só ele)
//   PAY_URL         (opcional) base da API; padrão = a da documentação da Laranjinha
//   PORT            (opcional) porta; padrão 8787
//   MOCK=1          modo teste: não chama a Laranjinha
//
// Rodar:  BOT_TOKEN=... PAY_KEY=... WEBHOOK_SECRET=... ORIGIN=https://seusite.com node server.js
//
// Rotas (o app só usa estas; todas exigem o header X-Telegram-Init-Data, validado com o token do bot):
//   POST /deposit {amount, payer:{name,document,email?}} -> {id, amount, pix, url, qr, expiresAt}
//   GET  /deposit/:id                                    -> {status: pending|paid|expired|failed, credited}
//   POST /webhook   (Laranjinha -> servidor, assinatura HMAC conferida)
const http = require('http'), crypto = require('crypto');
const { BOT_TOKEN, PAY_KEY, WEBHOOK_SECRET, MOCK, ORIGIN = '*', PORT = 8787 } = process.env;
const PAY_URL = (process.env.PAY_URL || 'https://mqvdjjbkjglaimbnpcer.supabase.co/functions/v1/api-proxy').replace(/\/$/, '');
if (!BOT_TOKEN) throw new Error('Defina BOT_TOKEN');
if (!MOCK && !PAY_KEY) throw new Error('Defina PAY_KEY (ou MOCK=1 para testar)');
if (!MOCK && !WEBHOOK_SECRET) console.warn('Aviso: sem WEBHOOK_SECRET o pagamento só é confirmado consultando a Laranjinha.');
if (!MOCK && ORIGIN === '*') console.warn('Aviso: defina ORIGIN com o endereço do seu site.');

const MIN = 10, MAX = 10000, BONUS = 1.005;
const charges = new Map(), hits = new Map(), seen = new Set(); // troque por banco de dados em produção
setInterval(() => { for (const [k, c] of charges) if (Date.now() > c.exp + 864e5) charges.delete(k); }, 36e5).unref();

// Valida o login do Telegram (HMAC com o token do bot). Retorna o usuário ou null.
function auth(init) {
  const p = new URLSearchParams(init || ''), hash = p.get('hash');
  if (!hash) return null;
  p.delete('hash');
  const dcs = [...p].map(([k, v]) => `${k}=${v}`).sort().join('\n');
  const secret = crypto.createHmac('sha256', 'WebAppData').update(BOT_TOKEN).digest();
  const mine = Buffer.from(crypto.createHmac('sha256', secret).update(dcs).digest('hex'));
  const given = Buffer.from(hash);
  if (mine.length !== given.length || !crypto.timingSafeEqual(mine, given)) return null;
  const ad = Number(p.get('auth_date'));
  if (!ad || Date.now() / 1000 - ad > 86400) return null;
  try { return JSON.parse(p.get('user')); } catch { return null; }
}

const cpfOk = c => {
  c = String(c || '').replace(/\D/g, '');
  if (c.length !== 11 || /^(\d)\1+$/.test(c)) return false;
  for (let t = 9; t < 11; t++) { let s = 0; for (let i = 0; i < t; i++) s += c[i] * (t + 1 - i); if ((s * 10 % 11) % 10 != c[t]) return false; }
  return true;
};
// A Laranjinha exige nome e CPF do pagador (erro invalid_payer). Validamos antes de chamar.
function payerOf(b) {
  const p = (b && b.payer) || {}, name = String(p.name || '').trim().replace(/\s+/g, ' '), doc = String(p.document || '').replace(/\D/g, ''), email = String(p.email || '').trim();
  if (name.length < 5 || name.length > 100 || name.split(' ').length < 2 || !cpfOk(doc)) return null;
  const o = { name, document: doc };
  if (email.length <= 120 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) o.email = email;
  return o;
}

// Chamada à Laranjinha: autenticação por header X-API-Key (conforme a documentação).
async function pay(method, path, body) {
  const r = await fetch(PAY_URL + path, {
    method, signal: AbortSignal.timeout(12000),
    headers: { 'X-API-Key': PAY_KEY, 'Content-Type': 'application/json' },
    body: body ? JSON.stringify(body) : undefined
  });
  const j = await r.json().catch(() => ({}));
  if (!r.ok || j.ok === false) { const e = new Error(`gateway ${r.status} ${j.error || ''}`); e.status = r.status; throw e; }
  return j;
}
async function createCharge(amount, user, payer, ref) {
  if (MOCK) return { id: ref, pix: `MOCK-${ref}-${amount.toFixed(2)}`, qr: null, exp: Date.now() + 15 * 60e3 };
  const j = await pay('POST', '/charges', {
    amount_cents: Math.round(amount * 100), description: 'Depósito Mega Bet', payer,
    metadata: { user_id: String(user.id), order_id: ref }
  });
  const c = j.charge;
  if (!c || !c.id || typeof c.qr_code !== 'string') throw new Error('resposta inesperada do gateway');
  return {
    id: c.id, pix: c.qr_code,
    qr: typeof c.qr_code_image === 'string' && c.qr_code_image.startsWith('data:image/') ? c.qr_code_image : null,
    exp: Date.parse(c.expires_at) || Date.now() + 15 * 60e3
  };
}

// Verifica se a chave está certa sem criar cobrança nenhuma (GET /me, da documentação). Cache de 60 s.
let gw = { ok: null, mode: null, at: 0 };
async function gwCheck() {
  if (MOCK) return (gw = { ok: true, mode: 'mock', at: Date.now() });
  try { const j = await pay('GET', '/me'); gw = { ok: true, mode: j.mode || 'live', at: Date.now() }; }
  catch (e) { gw = { ok: false, mode: null, at: Date.now(), err: e.status === 401 ? 'chave inválida ou revogada' : 'API da Laranjinha fora do ar' }; console.error('Laranjinha:', gw.err); }
  return gw;
}

// Confere a assinatura do webhook: header "t=<ts>,v1=<hex>", HMAC-SHA256 de "<ts>.<corpo cru>" com WEBHOOK_SECRET.
function sigOk(raw, h) {
  const ts = h['x-laranjinha-timestamp'], v1 = (String(h['x-laranjinha-signature'] || '').split(',').map(p => p.split('=')).find(p => p[0] === 'v1') || [])[1];
  if (!WEBHOOK_SECRET || !ts || !v1 || Math.abs(Date.now() / 1000 - Number(ts)) > 300) return false;
  const exp = Buffer.from(crypto.createHmac('sha256', WEBHOOK_SECRET).update(`${ts}.${raw}`).digest('hex')), got = Buffer.from(v1);
  return exp.length === got.length && crypto.timingSafeEqual(exp, got);
}

const send = (res, code, obj) => {
  res.writeHead(code, {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': ORIGIN,
    'Access-Control-Allow-Headers': 'Content-Type,X-Telegram-Init-Data',
    'Access-Control-Allow-Methods': 'GET,POST,OPTIONS'
  });
  res.end(JSON.stringify(obj));
};
const readRaw = req => new Promise(ok => {
  let d = '';
  req.on('data', c => { d += c; if (d.length > 1e5) req.destroy(); });
  req.on('end', () => ok(d));
});
const readBody = async req => { try { return JSON.parse((await readRaw(req)) || '{}'); } catch { return {}; } };

http.createServer(async (req, res) => {
  try {
    if (req.method === 'OPTIONS') return send(res, 204, {});
    const u = new URL(req.url, 'http://x');

    if (req.method === 'POST' && u.pathname === '/webhook') {
      const raw = await readRaw(req);
      if (!sigOk(raw, req.headers)) return send(res, 401, { error: 'assinatura inválida' });
      let d; try { d = JSON.parse(raw); } catch { return send(res, 400, { error: 'json' }); }
      const delivery = req.headers['x-laranjinha-delivery'] || d.id;
      if (delivery && seen.has(delivery)) return send(res, 200, { ok: 1 }); // reentrega: já processada
      if (delivery) { seen.add(delivery); if (seen.size > 5000) seen.delete(seen.values().next().value); }
      const ev = d.data || {};
      if (d.event === 'sale.paid') {
        const c = charges.get(ev.intent_id);
        if (c && ev.amount_cents === Math.round(c.amount * 100)) c.status = 'paid'; // valor precisa bater
        else console.error('webhook ignorado: cobrança desconhecida ou valor diferente');
      }
      return send(res, 200, { ok: 1 }); // sempre 2xx após assinatura válida, para não gerar reentrega
    }
    if (MOCK && req.method === 'POST' && u.pathname.startsWith('/mock/pay/')) { // só existe em MOCK=1
      const c = charges.get(u.pathname.split('/').pop());
      if (c) c.status = 'paid';
      return send(res, 200, { ok: !!c });
    }

    if (req.method === 'GET' && u.pathname === '/health') { // abra no navegador para conferir se está tudo certo
      if (Date.now() - gw.at > 60e3) await gwCheck();
      return send(res, 200, { ok: true, gateway: gw.ok ? 'ok' : 'erro', mode: gw.mode, aviso: gw.ok ? undefined : gw.err });
    }

    const user = auth(req.headers['x-telegram-init-data']);
    if (!user) return send(res, 401, { error: 'Sessão inválida. Abra o app pelo bot.', code: 'auth' });

    if (req.method === 'POST' && u.pathname === '/deposit') {
      const b = await readBody(req), amount = Math.round(Number(b.amount) * 100) / 100;
      if (!(amount >= MIN && amount <= MAX)) return send(res, 400, { error: 'Valor inválido (R$ 10 a R$ 10.000)', code: 'invalid_amount' });
      const payer = payerOf(b);
      if (!payer) return send(res, 400, { error: 'Informe nome completo e CPF válidos em Dados.', code: 'invalid_payer' });
      const now = Date.now(), h = (hits.get(user.id) || []).filter(t => now - t < 60e3);
      if (h.length >= 5) return send(res, 429, { error: 'Muitas tentativas. Aguarde 1 minuto.', code: 'rate_limit' });
      h.push(now); hits.set(user.id, h);
      let ch;
      try { ch = await createCharge(amount, user, payer, crypto.randomUUID()); }
      catch (e) { console.error('gateway:', e.message); return send(res, 502, { error: 'Falha ao gerar o PIX. Tente novamente.', code: 'provider_error' }); }
      charges.set(ch.id, { uid: user.id, amount, status: 'pending', exp: ch.exp, chk: 0 });
      return send(res, 200, { id: ch.id, amount, pix: ch.pix, url: null, qr: ch.qr, expiresAt: ch.exp });
    }

    const m = u.pathname.match(/^\/deposit\/([\w-]+)$/);
    if (req.method === 'GET' && m) {
      const c = charges.get(m[1]);
      if (!c || c.uid !== user.id) return send(res, 404, { error: 'not found' });
      if (c.status === 'pending' && !MOCK && Date.now() - c.chk > 3000) { // consulta a Laranjinha (não depende só do webhook)
        c.chk = Date.now();
        try {
          const j = await pay('GET', '/charges/' + encodeURIComponent(m[1])), s = (j.charge || j).status;
          if (s === 'paid' || s === 'expired' || s === 'failed') c.status = s;
        } catch (e) { console.error('consulta:', e.message); }
      }
      const status = c.status === 'pending' && Date.now() > c.exp + 30e3 ? 'expired' : c.status;
      return send(res, 200, { status, credited: status === 'paid' ? Math.round(c.amount * BONUS * 100) / 100 : 0 });
    }
    send(res, 404, { error: 'not found' });
  } catch (e) {
    console.error('erro:', e.message); // nunca registre chaves ou tokens
    send(res, 500, { error: 'Erro interno' });
  }
}).listen(PORT, () => { console.log('ok ' + PORT); gwCheck().then(g => console.log(g.ok ? 'Laranjinha conectada (modo ' + g.mode + ')' : 'ATENÇÃO: ' + g.err)); });
