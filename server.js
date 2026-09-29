/**
 * ════════════════════════════════════════════════════════════════════
 *  مسلم AI — خادم الإنتاج الآمن (Secure Production Server)
 * ════════════════════════════════════════════════════════════════════ */
'use strict';

require('dotenv').config();
const express  = require('express');
const path     = require('path');
const crypto   = require('crypto');

/* ── متغيرات البيئة ─────────────────────────────────────────────── */
const PORT         = parseInt(process.env.PORT || '3000', 10);
const LLM_API_KEY  = process.env.LLM_API_KEY  || '';
const LLM_BASE_URL = process.env.LLM_BASE_URL || 'https://api.groq.com/openai/v1';
const LLM_MODEL    = process.env.LLM_MODEL    || 'llama-3.3-70b-versatile';
const ADMIN_CODE   = process.env.ADMIN_CODE   || '';
const MAX_BODY     = 256 * 1024;

if (!LLM_API_KEY) console.warn('WARN: LLM_API_KEY غير مضبوط');
if (!ADMIN_CODE)  console.warn('WARN: ADMIN_CODE غير مضبوط — لوحة التحكم معطلة');

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1);

/* ── رؤوس الأمان ─────────────────────────────────────────────────── */
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'camera=(), geolocation=()');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  next();
});

app.use(express.json({ limit: MAX_BODY, strict: true }));

/* ── Rate Limiting ──────────────────────────────────────────────── */
const buckets = new Map();
setInterval(() => buckets.clear(), 60 * 1000).unref();
function rateLimit({ windowMs = 60000, max = 30 } = {}) {
  return (req, res, next) => {
    const ip  = req.ip || 'unknown';
    const now = Date.now();
    let b = buckets.get(ip);
    if (!b || now - b.start > windowMs) { b = { start: now, count: 0 }; buckets.set(ip, b); }
    if (++b.count > max) return res.status(429).json({ error: 'تم تجاوز عدد الطلبات المسموح' });
    next();
  };
}
const chatLimiter  = rateLimit({ max: 15 });
const adminLimiter = rateLimit({ max: 10 });
const lightLimiter = rateLimit({ max: 60 });

/* ── مصادر لوحة التحكم ──────────────────────────────────────────── */
let ADMIN_SOURCES = {};
try { ADMIN_SOURCES = require('./data/sources.json'); } catch (e) {}

/* ── الحالات المحظورة ───────────────────────────────────────────── */
const REFERRAL_CATEGORIES = [
  { id: 'talaq',   label: 'الأحوال الشخصية والطلاق',      re: /طلاق|خلع|كناي[ةت]|الرجعي[ة]?/ },
  { id: 'mirath',  label: 'المواريث والتركات',            re: /ميراث|ترك[ةه]|ورث[ةه]|وصي[ةه]/ },
  { id: 'hadsana', label: 'الحضانة والنفقة',              re: /حضان[ةه]|نفقة/ },
  { id: 'qisas',   label: 'الدماء والقصاص والديات',       re: /قصاص|دية|جناية|قتل (عمد|خطأ)/ },
  { id: 'takfir',  label: 'دعاوى التكفير والتفسيق',       re: /كفر ب|مكفّر|تكفير|مرتد/ },
  { id: 'qadhf',   label: 'الشهادات والقذف',              re: /قذف|زنى ب|شهادة زور/ },
  { id: 'crypto',  label: 'العقود المالية المعقدة',       re: /عملات رقمية|بيتكوين|كريبتو|فيوتشرز|futures/ },
  { id: 'debts',   label: 'النزاعات المالية بين الأفراد',  re: /تنازع مالي|ديون متنازع/ },
  { id: 'suicide', label: 'الأفكار الانتحارية',           re: /انتحار|أنهي حياتي|اقتل نفسي|لا أريد الحياة/ },
  { id: 'sihr',    label: 'السحر والمس',                  re: /سحر|مسّني|عين|حسد مرض/ },
  { id: 'medical', label: 'المسائل الطبية المعقدة',       re: /إجهاض|موت دماغي|نقل أعضاء|تحديد نسب/ },
];
const REFERRAL_MESSAGE =
  'عذراً، هذه المسألة تتطلب دراسة شخصية وسماع التفاصيل من عالم مختص. ' +
  'ننصحك بالتواصل المباشر مع الجهات الإفتائية المعتمدة.';
const DISCLAIMER = 'هذا النظام للمساعدة والمعرفة العامة فقط، ولا يُعتبر بديلاً عن الفتوى الشرعية الصادرة من العلماء المختصين أو القضاء.';
const NO_DOC_ANSWER = 'لا تتوفر إجابة موثقة لهذا السؤال';

function detectReferral(text) {
  if (!text) return null;
  for (const c of REFERRAL_CATEGORIES) if (c.re.test(text)) return c;
  return null;
}

const INJECTION_RE = /(system\s*prompt|ignore\s+(all|previous)\s+instructions|DAN\s+mode|jailbreak|تجاهل\s+(كل|جميع)?\s*(التعليمات|الأوامر)|انسَ\s+تعليمات|اكسر\s+القيود)/i;

function cleanStr(v, max = 4000) {
  return String(v ?? '').replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, '').slice(0, max).trim();
}
const MAX_MSG = 20, MAX_MSG_LEN = 8000;
function validHistory(messages) {
  return Array.isArray(messages) && messages.length <= MAX_MSG &&
    messages.every(m => m && (m.role === 'user' || m.role === 'assistant') &&
      typeof m.content === 'string' && m.content.length <= MAX_MSG_LEN);
}
const ALLOWED_MODES = new Set(['fatwa','smart','debate','halal','learn','fin','hadith-check',
  'hadith-explain','tafsir','irab','quiz','book','content-check','sharp-reply','did-say',
  'dawah','deep-search','img','needmore']);
const SOURCE_SCOPES = {
  'ibn-baz' : 'الشيخ ابن باز — فتاوى نور على الدرب واللجنة الدائمة',
  'islamqa' : 'موقع الإسلام سؤال وجواب',
  'shamela' : 'المكتبة الشاملة (الكتب الشرعية المعتمدة)',
  'islamweb': 'موقع إسلام ويب (فتاوى المعاصرين)',
  'all'     : 'جميع المصادر المعتمدة: ابن باز، الإسلام سؤال وجواب، المكتبة الشاملة، إسلام ويب',
};
function sourcesInstruction(scope) {
  return 'الزم المصادر التالية حصرياً ولا تجب إلا منها: ' +
    (SOURCE_SCOPES[scope] || SOURCE_SCOPES.all) + '. ' +
    'إن لم تجد الإجابة في هذه المصادر فاكتب حرفياً: "' + NO_DOC_ANSWER + '" ولا تخترع إجابة.';
}

const MODELS = [
  { id: 'default', label: 'مسلم AI — الافتراضي',    vision: false },
  { id: 'vision',  label: 'مسلم AI — مخصص الصور',   vision: true  },
  { id: 'fast',    label: 'مسلم AI — سريع ومتوازن', vision: false },
];
app.get('/api/models', lightLimiter, (req, res) => res.json(MODELS));

/* ── استدعاء النموذج ────────────────────────────────────────────── */
const PROVIDERS = [
  { name:'primary', key: process.env.LLM_API_KEY, base: LLM_BASE_URL, model: LLM_MODEL },
  { name:'openrouter', key: process.env.OPENROUTER_API_KEY, base: 'https://openrouter.ai/api/v1',
    model: process.env.OPENROUTER_MODEL || 'meta-llama/llama-3.3-70b-instruct:free' },
  { name:'gemini', key: process.env.GEMINI_API_KEY,
    base: 'https://generativelanguage.googleapis.com/v1beta/openai/',
    model: process.env.GEMINI_MODEL || 'gemini-2.0-flash' },
];
async function callOne(p, messages, opts) {
  const ctrl = new AbortController();
  const to = setTimeout(() => ctrl.abort(), 55000);
  try {
    const headers = { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + p.key };
    const r = await fetch(p.base.replace(/\/$/, '') + '/chat/completions', {
      method: 'POST', signal: ctrl.signal, headers,
      body: JSON.stringify({ model: p.model, messages, temperature: 0.2, max_tokens: opts.maxTokens || 3000 }),
    });
    if (!r.ok) throw new Error(p.name + ' ' + r.status);
    const d = await r.json();
    const answer = d && d.choices && d.choices[0] && d.choices[0].message ? (d.choices[0].message.content || '') : '';
    if (!answer) throw new Error(p.name + ' empty');
    return { answer, sources: [], grounded: true };
  } finally { clearTimeout(to); }
}
async function callLLM(messages, opts = {}) {
  const alive = PROVIDERS.filter(p => p.key);
  if (!alive.length) return { answer: NO_DOC_ANSWER, sources: [], grounded: true };
  for (const p of alive) {
    try { return await callOne(p, messages, opts); }
    catch (e) { console.error('provider failed:', e.message); }
  }
  throw new Error('all providers down');
}

function buildSystemPrompt({ mode, scope, madhhab, customInstructions }) {
  const parts = [
    'أنت "مسلم AI"، مساعد شرعي يجيب حصرياً من المصادر الموثقة المحددة من إدارة التطبيق.',
    DISCLAIMER,
    sourcesInstruction(scope),
    'لا تُصدر فتوى مستقلة؛ اعرض أقوال أهل العلم بمصادرها، واذكر الخلاف عند وجوده.',
    'لا تجب أبداً عن: الطلاق والمواريث والحضانة والقصاص والتكفير والقذف والعقود المعقدة والمسائل الطبية المعقدة — هذه تُحال لعالم مختص.',
  ];
  if (mode === 'quiz')   parts.push('أنشئ أسئلة الاختبار JSON فقط كما هو مطلوب، والتزم بمستوى الصعوبة المطلوب.');
  if (mode === 'debate') parts.push('مثّل الإسلام بحكمة واختم بسؤال منطقي.');
  if (mode === 'sharp-reply') parts.push('رد قاطع مقنع بلغة عامية بسيطة.');
  if (madhhab && madhhab !== 'jumhur') parts.push('راعِ المذهب الفقهي المختار: ' + madhhab + ' مع ذكر الخلاف.');
  if (customInstructions) parts.push('تعليمات المستخدم: ' + customInstructions.slice(0, 1500));
  return parts.join('\n');
}

/* ── /api/chat ───────────────────────────────────────────────────── */
app.post('/api/chat', chatLimiter, async (req, res) => {
  try {
    const b = req.body || {};
    if (typeof b !== 'object') return res.status(400).json({ error: 'طلب غير صالح' });
    if (!validHistory(b.messages)) return res.status(400).json({ error: 'صيغة المحادثة غير صالحة' });
    const mode    = ALLOWED_MODES.has(b.mode) ? b.mode : 'fatwa';
    const scope   = SOURCE_SCOPES[b.scope] ? b.scope : 'all';
    const madhhab = cleanStr(b.madhhab, 30) || 'jumhur';
    const lastUser = b.messages.slice().reverse().find(m => m.role === 'user');
    const userText = cleanStr(lastUser && lastUser.content, MAX_MSG_LEN);

    const fullText = userText + ' ' + b.messages.map(m => m.content).join(' ').slice(0, 20000);
    if (INJECTION_RE.test(fullText)) return res.status(400).json({ error: 'تم رصد محاولة تجاوز للتعليمات' });

    const referral = detectReferral(userText);
    if (referral) {
      return res.json({ answer: REFERRAL_MESSAGE, referral: true, category: referral.label,
        openMuftis: true, sources: [], grounded: true, disclaimer: DISCLAIMER });
    }

    const customInstr = cleanStr(b.customInstructions, 1500);
    const sys = { role: 'system', content: buildSystemPrompt({ mode, scope, madhhab, customInstructions: customInstr }) };
    const history = b.messages.map(m => ({ role: m.role, content: m.content.slice(0, MAX_MSG_LEN) }));

    let out;
    try { out = await callLLM([sys].concat(history), { maxTokens: mode === 'quiz' ? 4000 : 3000 }); }
    catch (e2) { return res.json({ answer: NO_DOC_ANSWER, sources: [], grounded: true }); }

    const answer = cleanStr(out.answer, 12000);
    if (!answer || answer.length < 3) return res.json({ answer: NO_DOC_ANSWER, sources: [], grounded: true });
    res.json({ answer, sources: (out.sources || []).slice(0, 8), grounded: out.grounded !== false,
      disclaimer: DISCLAIMER, ...(mode === 'quiz' ? { quiz: safeParseQuiz(answer) } : {}) });
  } catch (e) {
    console.error('chat error:', e.message);
    res.status(500).json({ error: 'تعذر توليد الإجابة الآن' });
  }
});

function safeParseQuiz(text) {
  try {
    const m = text.match(/\[[\s\S]*\]/);
    const arr = m ? JSON.parse(m[0]) : JSON.parse(text);
    if (!Array.isArray(arr)) return [];
    return arr.slice(0, 60).map(q => ({
      q: cleanStr(q.q || q.question, 500),
      choices: Array.isArray(q.choices) ? q.choices.slice(0, 8).map(c => cleanStr(c, 200)) : [],
      a: cleanStr(q.a || q.answer, 1000),
      type: ['mcq','tf','essay'].includes(q.type) ? q.type : undefined,
    }));
  } catch (e) { return []; }
}

app.post('/api/name', lightLimiter, async (req, res) => {
  try {
    if (!validHistory(req.body && req.body.messages)) return res.status(400).json({ error: 'صيغة غير صالحة' });
    const out = await callLLM([
      { role: 'system', content: 'أعطِ عنواناً لمحادثة شرعية في 6 كلمات كحد أقصى — نص عربي فقط بدون تنسيق.' },
      ...req.body.messages.slice(-4),
    ], { maxTokens: 40 });
    res.json({ name: cleanStr(out.answer, 60).replace(/["«»]/g, '') || 'محادثة جديدة' });
  } catch (e) { res.status(500).json({ error: 'تعذر التسمية' }); }
});

app.post('/api/tafsir', lightLimiter, async (req, res) => {
  const text = cleanStr(req.body && req.body.text, 500);
  if (!text) return res.status(400).json({ error: 'نص غير صالح' });
  try {
    const out = await callLLM([
      { role: 'system', content: sourcesInstruction('shamela') + ' اشرح النص القرآني أو الحديثي من كتب التفسير والشروح المعتمدة فقط، واذكر المصدر. إن لم تجد فقل: ' + NO_DOC_ANSWER },
      { role: 'user', content: text },
    ], { maxTokens: 1200 });
    res.json({ answer: cleanStr(out.answer, 4000), source: 'المكتبة الشاملة' });
  } catch (e) { res.status(500).json({ error: 'تعذر جلب الشرح' }); }
});

/* ── API الأدمن ─────────────────────────────────────────────────── */
const adminSessions = new Map();
function adminAuth(req, res, next) {
  const t = String(req.headers['x-admin-token'] || '');
  const exp = adminSessions.get(t);
  if (!exp || exp < Date.now()) return res.status(401).json({ error: 'غير مصرح' });
  next();
}
app.post('/api/admin/login', adminLimiter, (req, res) => {
  const code = cleanStr(req.body && req.body.code, 100);
  if (!ADMIN_CODE || !code) return res.status(401).json({ error: 'رمز الدخول غير صحيح' });
  const ok = crypto.timingSafeEqual(
    crypto.createHash('sha256').update(code).digest(),
    crypto.createHash('sha256').update(ADMIN_CODE).digest());
  if (!ok) return res.status(401).json({ error: 'رمز الدخول غير صحيح' });
  const token = crypto.randomBytes(32).toString('hex');
  adminSessions.set(token, Date.now() + 2 * 60 * 60 * 1000);
  res.json({ token, expiresIn: 7200 });
});
app.get('/api/admin/sources', adminAuth, (req, res) => res.json(ADMIN_SOURCES));
app.post('/api/admin/sources', adminAuth, (req, res) => {
  const b = req.body;
  if (!b || typeof b !== 'object' || Array.isArray(b)) return res.status(400).json({ error: 'صيغة غير صالحة' });
  if (JSON.stringify(b).length > 2 * 1024 * 1024) return res.status(413).json({ error: 'الحجم كبير جداً' });
  ADMIN_SOURCES = b;
  try {
    require('fs').mkdirSync('./data', { recursive: true });
    require('fs').writeFileSync('./data/sources.json', JSON.stringify(b));
  } catch (e) {}
  res.json({ ok: true });
});
app.get('/api/madhabs', lightLimiter, (req, res) => {
  const all = [];
  Object.values(ADMIN_SOURCES).forEach(f => (f.items || []).forEach(it => all.push(String(it.n || ''))));
  const madhabs = {};
  const MAP = [
    ['hanafi',  /الهداية|المرغيناني|الكاساني|بدائع الصنائع|القدوري/],
    ['maliki',  /المدونة|سحنون|الموطأ|الدردير|الحطاب/],
    ['shafii',  /المنهاج|النووي|تحفة المحتاج|روضة الطالبين/],
    ['hanbali', /المغني|ابن قدامة|كشاف القناع|الإنصاف|الروض المربع/],
  ];
  MAP.forEach(([k, re]) => {
    const books = all.filter(n => re.test(n)).slice(0, 12);
    if (books.length) madhabs[k] = books;
  });
  res.json(madhabs);
});

/* ── ملفات الموقع الثابتة (من الروت — مع حماية الملفات الحساسة) ── */
const BLOCKED = /^\/(server\.js|package(-lock)?\.json|vercel\.json|\.env|\.git|node_modules|data)(\/|$)/i;
app.use((req, res, next) => {
  if (BLOCKED.test(req.path)) return res.status(404).json({ error: 'غير موجود' });
  next();
});
app.use(express.static(__dirname, {
  maxAge: '1h',
  setHeaders(res, fp) { if (fp.endsWith('.html')) res.setHeader('Cache-Control', 'no-store'); },
}));
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'Muslim.html')));

/* ── 404 + معالج أخطاء ──────────────────────────────────────────── */
app.use((req, res) => res.status(404).json({ error: 'غير موجود' }));
app.use((err, req, res, next) => {
  if (err && err.type === 'entity.too.large') return res.status(413).json({ error: 'حجم الطلب كبير جداً' });
  if (err && err.type === 'entity.parse.failed') return res.status(400).json({ error: 'JSON غير صالح' });
  console.error('unhandled:', err && err.message);
  res.status(500).json({ error: 'خطأ داخلي في الخادم' });
});

/* ── قاعدة البيانات الخفيفة + مصادقة المستخدمين ────────────────── */
const fs2 = require('fs');
const DB_PATH = path.join(__dirname, 'data', 'db.json');
let DB = { users: {}, community: [], global: {} };
try { DB = JSON.parse(fs2.readFileSync(DB_PATH, 'utf8')); } catch (e) {}
let dbSaveT = null;
function dbSave() {
  clearTimeout(dbSaveT);
  dbSaveT = setTimeout(() => {
    try {
      fs2.mkdirSync(path.dirname(DB_PATH), { recursive: true });
      const tmp = DB_PATH + '.tmp';
      fs2.writeFileSync(tmp, JSON.stringify(DB));
      fs2.renameSync(tmp, DB_PATH);
    } catch (e) { console.error('db save failed:', e.message); }
  }, 400);
}
const AUTH_SECRET = process.env.AUTH_SECRET || crypto.randomBytes(32).toString('hex');
function signTok(email) {
  const exp = Date.now() + 7 * 24 * 3600 * 1000;
  const body = email + '|' + exp;
  return body + '|' + crypto.createHmac('sha256', AUTH_SECRET).update(body).digest('base64url');
}
function verifyTok(tok) {
  const p = String(tok || '').split('|');
  if (p.length !== 3) return null;
  const expect = crypto.createHmac('sha256', AUTH_SECRET).update(p[0] + '|' + p[1]).digest('base64url');
  const a = Buffer.from(p[2]), b = Buffer.from(expect);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  if (+p[1] < Date.now()) return null;
  return p[0];
}
function userAuth(req, res, next) {
  const email = verifyTok(String(req.headers['authorization'] || '').replace(/^Bearer\s+/i, ''));
  if (!email || !DB.users[email]) return res.status(401).json({ error: 'جلسة غير صالحة' });
  req.userEmail = email;
  next();
}
function hashPass(pass, salt) {
  salt = salt || crypto.randomBytes(16).toString('hex');
  return { salt, h: crypto.scryptSync(String(pass), salt, 32).toString('hex') };
}
const SKIP_KEYS = new Set(['mai_token','mai_pub_draft','mai_quran_ask']);
function syncable(k){ return typeof k==='string' && k.indexOf('mai_')===0 && !SKIP_KEYS.has(k); }
const GLOBAL_KEYS = new Set(['mai_admin_sources_v4','mai_admin_instructions','mai_feature_toggles',
  'mai_suggs','mai_maintenance','mai_maintenance_msg','mai_muftis_custom','mai_muftis_hidden']);

app.post('/api/auth/register', lightLimiter, (req, res) => {
  const name  = cleanStr(req.body && req.body.name, 60);
  const email = cleanStr(req.body && req.body.email, 120).toLowerCase();
  const pass  = String((req.body && req.body.pass) || '');
  if (!name || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email) || pass.length < 6)
    return res.status(400).json({ error: 'بيانات غير صالحة (كلمة المرور 6+ أحرف)' });
  if (DB.users[email]) return res.status(409).json({ error: 'هذا البريد مسجل مسبقاً' });
  const { salt, h } = hashPass(pass);
  DB.users[email] = { name, salt, hash: h, created: Date.now(), data: {} };
  dbSave();
  res.json({ token: signTok(email) });
});

app.post('/api/auth/login', lightLimiter, (req, res) => {
  const email = cleanStr(req.body && req.body.email, 120).toLowerCase();
  const pass  = String((req.body && req.body.pass) || '');
  const u = DB.users[email];
  if (!u) return res.status(401).json({ error: 'بريد أو كلمة مرور غير صحيحة' });
  const { h } = hashPass(pass, u.salt);
  const a = Buffer.from(h), b = Buffer.from(u.hash);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b))
    return res.status(401).json({ error: 'بريد أو كلمة مرور غير صحيحة' });
  res.json({ token: signTok(email), name: u.name });
});

app.get('/api/data', userAuth, (req, res) => res.json({ data: DB.users[req.userEmail].data || {} }));
app.put('/api/data', userAuth, (req, res) => {
  const b = req.body;
  if (!b || typeof b !== 'object' || Array.isArray(b)) return res.status(400).json({ error: 'صيغة غير صالحة' });
  if (JSON.stringify(b).length > 8 * 1024 * 1024) return res.status(413).json({ error: 'البيانات كبيرة جداً' });
  const u = DB.users[req.userEmail];
  u.data = u.data || {};
  let n = 0;
  for (const k of Object.keys(b)) { if (syncable(k) && !GLOBAL_KEYS.has(k)) { u.data[k] = b[k]; n++; } }
  dbSave();
  res.json({ ok: true, saved: n });
});

app.get('/api/community', lightLimiter, (req, res) => res.json({ posts: DB.community.slice(0, 500) }));
app.put('/api/community', userAuth, (req, res) => {
  const posts = req.body && req.body.posts;
  if (!Array.isArray(posts) || JSON.stringify(posts).length > 2 * 1024 * 1024)
    return res.status(400).json({ error: 'صيغة غير صالحة' });
  DB.community = posts.slice(0, 500).map(p => ({
    id: +p.id || Date.now(), type: cleanStr(p.type, 20), title: cleanStr(p.title, 120),
    content: cleanStr(p.content, 8000), author: cleanStr(p.author, 60),
    ts: +p.ts || Date.now(), mine: !!p.mine, up: Math.max(0, +p.up || 0), down: Math.max(0, +p.down || 0),
  }));
  dbSave();
  res.json({ ok: true });
});

app.get('/api/global', lightLimiter, (req, res) => {
  const g = DB.global || {};
  const out = {};
  GLOBAL_KEYS.forEach(k => { if (g[k] !== undefined) out[k] = g[k]; });
  res.json(out);
});
app.put('/api/global', adminAuth, (req, res) => {
  const b = req.body;
  if (!b || typeof b !== 'object' || Array.isArray(b)) return res.status(400).json({ error: 'صيغة غير صالحة' });
  if (JSON.stringify(b).length > 4 * 1024 * 1024) return res.status(413).json({ error: 'الحجم كبير جداً' });
  DB.global = DB.global || {};
  let n = 0;
  for (const k of Object.keys(b)) { if (GLOBAL_KEYS.has(k)) { DB.global[k] = b[k]; n++; } }
  dbSave();
  res.json({ ok: true, saved: n });
});

app.listen(PORT, () => {
  console.log('OK: مسلم AI يعمل على http://localhost:' + PORT);
  console.log('LOCK: لوحة التحكم admin.html (الرمز من ADMIN_CODE)');
});
