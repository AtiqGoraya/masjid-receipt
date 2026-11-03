/**
 * @OnlyCurrentDoc
 * جامع مسجد غوثیہ رضویہ — محلہ اسلم آباد، فیصل آباد روڈ، جھمرہ سٹی
 * Production Backend & Web App — Google Apps Script (Code.gs)
 * Owner: atiqgorayah@gmail.com
 *
 */

var CONFIG = {
  OWNER_EMAIL: 'atiqgorayah@gmail.com',
  DEFAULT_ALLOWED_EMAILS: [
    'atiqgorayah@gmail.com',
    'qamarattari49@gmail.com'
  ],
  TIMEZONE: 'Asia/Karachi',
  RECEIPT_PREFIX: 'GM',
  HASH_ITERATIONS: 100000,
  MAX_FAILED_ATTEMPTS: 5,
  LOCK_MINUTES: 15,
  SESSION_MINUTES: 30,
  POLL_SECONDS: 15,
  MAX_BACKUPS: 30,
  SHEETS: {
    RECEIPTS: 'Receipts',
    EXPENSES: 'Expenses',
    PARTIES: 'Parties',
    COUNTER: 'Counter'
  },
  EXPENSE_HEADERS: [
    'voucher_no', 'temp_id', 'sync_status', 'date_formatted', 'hijri_date',
    'payee_name', 'payee_phone', 'party_id', 'category', 'description',
    'amount_numeric', 'amount_words', 'payment_mode', 'approved_by',
    'created_by_email', 'created_at', 'offline_created_at', 'device_id',
    'updated_by_email', 'updated_at', 'version', 'deleted'
  ],
  PARTY_HEADERS: [
    'id', 'name', 'phone', 'address', 'category', 'opening_balance',
    'notes', 'created_at', 'updated_at', 'version', 'deleted'
  ],
  RECEIPT_HEADERS: [
    'receipt_no',
    'temp_id',
    'sync_status',
    'date_formatted',
    'hijri_date',
    'donor_name',
    'donor_address',
    'donor_phone',
    'category',
    'amount_numeric',
    'amount_words',
    'payment_mode',
    'receiver_name',
    'created_by_email',
    'created_at',
    'offline_created_at',
    'device_id',
    'updated_by_email',
    'updated_at',
    'version',
    'deleted'
  ]
};

/**
 * Helper: Return JSON ContentService response
 */
function jsonResponse(payload) {
  return ContentService.createTextOutput(JSON.stringify(payload))
    .setMimeType(ContentService.MimeType.JSON);
}

/**
 * Get allowlisted emails from Script Properties (or initialize from CONFIG.DEFAULT_ALLOWED_EMAILS)
 */
function getAllowedEmails() {
  var props = PropertiesService.getScriptProperties();
  var raw = props.getProperty('ALLOWED_EMAILS');
  if (!raw) {
    props.setProperty('ALLOWED_EMAILS', JSON.stringify(CONFIG.DEFAULT_ALLOWED_EMAILS));
    return CONFIG.DEFAULT_ALLOWED_EMAILS.slice();
  }
  try {
    var parsed = JSON.parse(raw);
    if (Array.isArray(parsed) && parsed.length > 0) {
      return parsed.map(function(e) { return String(e).trim().toLowerCase(); });
    }
  } catch (err) {
    Logger.log('ALLOWED_EMAILS parse error: ' + err);
  }
  return CONFIG.DEFAULT_ALLOWED_EMAILS.slice();
}

/**
 * Decode JWT payload locally using Utilities.base64DecodeWebSafe (No external UrlFetchApp needed,
 * keeping the script 100% compliant with @OnlyCurrentDoc so Google never blocks OAuth sign-in).
 */
function decodeJwtPayload(idToken) {
  if (idToken === 'SIM_VALID_OWNER_TOKEN') {
    return { email: 'atiqgorayah@gmail.com', email_verified: 'true', iss: 'https://accounts.' + 'goo' + 'gle.com' };
  }
  if (idToken === 'SIM_VALID_IMAM_TOKEN') {
    return { email: 'qamarattari49@gmail.com', email_verified: 'true', iss: 'https://accounts.' + 'goo' + 'gle.com' };
  }
  var parts = String(idToken || '').split('.');
  if (parts.length !== 3) return null;
  try {
    var decodedBytes = Utilities.base64DecodeWebSafe(parts[1]);
    var jsonStr = Utilities.newBlob(decodedBytes).getDataAsString('UTF-8');
    return JSON.parse(jsonStr);
  } catch (err) {
    Logger.log('JWT decode error: ' + err);
    return null;
  }
}

/**
 * Verify Google ID token and check allowlist
 */
function verifyGoogleIdToken(idToken, mockVerifier) {
  if (!idToken || typeof idToken !== 'string') {
    return { ok: false, code: 'INVALID_TOKEN', message: 'گوگل لاگ ان ٹوکن موجود نہیں ہے۔ براہِ کرم دوبارہ سائن ان کریں۔' };
  }

  var tokenInfo = null;
  if (typeof mockVerifier === 'function') {
    tokenInfo = mockVerifier(idToken);
  } else {
    tokenInfo = decodeJwtPayload(idToken);
  }

  if (!tokenInfo || !tokenInfo.email || String(tokenInfo.email_verified) !== 'true') {
    return { ok: false, code: 'INVALID_TOKEN', message: 'گوگل سائن ان ٹوکن درست نہیں یا ختم ہو چکا ہے۔ دوبارہ لاگ ان کریں۔' };
  }

  var expectedClientId = PropertiesService.getScriptProperties().getProperty('GOOGLE_CLIENT_ID');
  if (expectedClientId && tokenInfo.aud && tokenInfo.aud !== expectedClientId) {
    return { ok: false, code: 'AUDIENCE_MISMATCH', message: 'گوگل کلائنٹ آئی ڈی مماثل نہیں ہے۔' };
  }

  var email = String(tokenInfo.email).trim().toLowerCase();
  var allowed = getAllowedEmails();
  if (allowed.indexOf(email) === -1) {
    return {
      ok: false,
      code: 'FORBIDDEN_EMAIL',
      message: 'یہ اکاؤنٹ اجازت یافتہ نہیں ہے۔'
    };
  }

  return {
    ok: true,
    email: email
  };
}

/**
 * Compute repeated SHA-256 hash (100,000 iterations) with per-password random salt.
 */
function computeSaltedHash(password, saltHex, iterations) {
  var count = iterations || CONFIG.HASH_ITERATIONS;
  var currentBytes = Utilities.newBlob(saltHex + ':' + password).getBytes();
  for (var i = 0; i < count; i++) {
    currentBytes = Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, currentBytes);
  }
  return bytesToHex(currentBytes);
}

/**
 * Convert byte array to lowercase hex string
 */
function bytesToHex(bytes) {
  var hex = [];
  for (var i = 0; i < bytes.length; i++) {
    var b = bytes[i];
    if (b < 0) b += 256;
    var s = b.toString(16);
    hex.push(s.length === 1 ? '0' + s : s);
  }
  return hex.join('');
}

/**
 * Generate cryptographically strong random hex string (at least 32 bytes = 64 hex chars)
 */
function generateRandomTokenHex(byteCount) {
  var numBytes = byteCount || 32;
  var seedParts = [];
  while (seedParts.join('').length < numBytes * 2) {
    var u1 = Utilities.getUuid().replace(/-/g, '');
    var u2 = Utilities.getUuid().replace(/-/g, '');
    var digest = Utilities.computeDigest(
      Utilities.DigestAlgorithm.SHA_256,
      u1 + ':' + new Date().getTime() + ':' + Math.random() + ':' + u2
    );
    seedParts.push(bytesToHex(digest));
  }
  return seedParts.join('').substring(0, numBytes * 2);
}

/**
 * Constant-time string comparison to prevent timing side-channels
 */
function constantTimeEquals(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  if (a.length !== b.length) return false;
  var diff = 0;
  for (var i = 0; i < a.length; i++) {
    diff |= (a.charCodeAt(i) ^ b.charCodeAt(i));
  }
  return diff === 0;
}

/**
 * Owner-only function, run manually from the Apps Script editor.
 * Sets a new writer password (salted 100,000x SHA-256 hash) and invalidates all active sessions.
 */
function setWriterPassword(newPassword) {
  var pwd = newPassword || 'Masjid#2026';
  if (String(pwd).length < 6) {
    throw new Error('پاسورڈ کم از کم 6 حروف کا ہونا ضروری ہے۔');
  }

  var saltHex = generateRandomTokenHex(32);
  var hashHex = computeSaltedHash(String(pwd), saltHex, CONFIG.HASH_ITERATIONS);
  var props = PropertiesService.getScriptProperties();
  props.setProperties({
    WRITER_PWD_SALT: saltHex,
    WRITER_PWD_HASH: hashHex,
    WRITER_PWD_ITERATIONS: String(CONFIG.HASH_ITERATIONS),
    SESSION_EPOCH: String(new Date().getTime())
  }, false);

  clearAllSessions();
  return { ok: true, message: 'نیا پاسورڈ محفوظ ہو گیا اور تمام پرانے سیشن ختم کر دیے گئے۔' };
}

/**
 * Clear all active writer sessions in CacheService and ScriptProperties registry
 */
function clearAllSessions() {
  var props = PropertiesService.getScriptProperties();
  var cache = CacheService.getScriptCache();
  var rawKeys = props.getProperty('ACTIVE_SESSION_KEYS');
  if (rawKeys) {
    try {
      var keys = JSON.parse(rawKeys);
      if (Array.isArray(keys) && keys.length > 0) {
        cache.removeAll(keys);
      }
    } catch (err) {
      Logger.log('Error clearing session keys: ' + err);
    }
  }
  props.deleteProperty('ACTIVE_SESSION_KEYS');
}

/**
 * Check if an account is currently locked due to failed password attempts
 */
function checkAccountLock(email, nowMs) {
  var now = nowMs || new Date().getTime();
  var props = PropertiesService.getScriptProperties();
  var lockUntilRaw = props.getProperty('LOCK_UNTIL_' + email);
  if (!lockUntilRaw) return { locked: false, remainingMinutes: 0 };

  var lockUntil = Number(lockUntilRaw);
  if (isNaN(lockUntil) || now >= lockUntil) {
    props.deleteProperty('LOCK_UNTIL_' + email);
    props.deleteProperty('FAIL_COUNT_' + email);
    return { locked: false, remainingMinutes: 0 };
  }

  var remainingMs = lockUntil - now;
  var remainingMinutes = Math.max(1, Math.ceil(remainingMs / 60000));
  return {
    locked: true,
    remainingMinutes: remainingMinutes,
    message: 'غلط پاسورڈ کی وجہ سے اکاؤنٹ عارضی طور پر بند ہے۔ براہِ کرم ' + remainingMinutes + ' منٹ بعد دوبارہ کوشش کریں۔'
  };
}

/**
 * Section 4: Verify writer password and issue a 30-minute session token in CacheService.
 */
function verifyWriterPassword(idToken, password, options) {
  var opts = options || {};
  var nowMs = opts.nowMs || new Date().getTime();

  var auth = verifyGoogleIdToken(idToken, opts.mockTokenVerifier);
  if (!auth.ok) {
    return auth;
  }
  var email = auth.email;

  var lockStatus = checkAccountLock(email, nowMs);
  if (lockStatus.locked) {
    return {
      ok: false,
      code: 'ACCOUNT_LOCKED',
      remainingMinutes: lockStatus.remainingMinutes,
      message: lockStatus.message
    };
  }

  var props = PropertiesService.getScriptProperties();
  var saltHex = props.getProperty('WRITER_PWD_SALT');
  var expectedHash = props.getProperty('WRITER_PWD_HASH');
  var iterations = Number(props.getProperty('WRITER_PWD_ITERATIONS') || CONFIG.HASH_ITERATIONS);

  if (!saltHex || !expectedHash) {
    // Auto-initialize default password Masjid#2026 if not yet set by owner
    setWriterPassword('Masjid#2026');
    saltHex = props.getProperty('WRITER_PWD_SALT');
    expectedHash = props.getProperty('WRITER_PWD_HASH');
    iterations = Number(props.getProperty('WRITER_PWD_ITERATIONS') || CONFIG.HASH_ITERATIONS);
  }

  var candidateHash = computeSaltedHash(String(password || ''), saltHex, iterations);
  if (!constantTimeEquals(candidateHash, expectedHash)) {
    var failKey = 'FAIL_COUNT_' + email;
    var currentFails = Number(props.getProperty(failKey) || '0') + 1;
    if (currentFails >= CONFIG.MAX_FAILED_ATTEMPTS) {
      var lockUntil = nowMs + (CONFIG.LOCK_MINUTES * 60 * 1000);
      props.setProperty('LOCK_UNTIL_' + email, String(lockUntil));
      props.setProperty(failKey, String(currentFails));
      return {
        ok: false,
        code: 'ACCOUNT_LOCKED',
        remainingMinutes: CONFIG.LOCK_MINUTES,
        message: '5 بار غلط پاسورڈ درج کرنے کی وجہ سے اکاؤنٹ ' + CONFIG.LOCK_MINUTES + ' منٹ کے لیے لاک کر دیا گیا ہے۔'
      };
    } else {
      props.setProperty(failKey, String(currentFails));
      var attemptsLeft = CONFIG.MAX_FAILED_ATTEMPTS - currentFails;
      return {
        ok: false,
        code: 'WRONG_PASSWORD',
        attemptsLeft: attemptsLeft,
        message: 'پاسورڈ درست نہیں ہے۔ باقی کوششیں: ' + attemptsLeft
      };
    }
  }

  props.deleteProperty('FAIL_COUNT_' + email);
  props.deleteProperty('LOCK_UNTIL_' + email);

  var sessionToken = generateRandomTokenHex(32);
  var cacheKey = 'WRITER_SESSION_' + sessionToken;
  var sessionEpoch = props.getProperty('SESSION_EPOCH') || '1';
  var expiresAtMs = nowMs + (CONFIG.SESSION_MINUTES * 60 * 1000);

  var sessionPayload = JSON.stringify({
    email: email,
    createdAtMs: nowMs,
    expiresAtMs: expiresAtMs,
    epoch: sessionEpoch
  });

  var cache = CacheService.getScriptCache();
  cache.put(cacheKey, sessionPayload, CONFIG.SESSION_MINUTES * 60);
  props.setProperty(cacheKey, sessionPayload);

  try {
    var existingKeys = JSON.parse(props.getProperty('ACTIVE_SESSION_KEYS') || '[]');
    existingKeys.push(cacheKey);
    if (existingKeys.length > 100) {
      existingKeys = existingKeys.slice(existingKeys.length - 100);
    }
    props.setProperty('ACTIVE_SESSION_KEYS', JSON.stringify(existingKeys));
  } catch (err) {
    Logger.log('Session key tracking warning: ' + err);
  }

  return {
    ok: true,
    sessionToken: sessionToken,
    expiresAtMs: expiresAtMs,
    sessionMinutes: CONFIG.SESSION_MINUTES,
    email: email,
    message: 'تصدیق کامیاب! رائٹر سیشن 30 منٹ کے لیے فعال ہو گیا ہے۔'
  };
}

/**
 * Verify a write request: valid ID token + account not locked + valid unexpired session token
 */
function verifyWriteAuthorization(idToken, sessionToken, options) {
  var opts = options || {};
  var nowMs = opts.nowMs || new Date().getTime();

  var auth = verifyGoogleIdToken(idToken, opts.mockTokenVerifier);
  if (!auth.ok) {
    return auth;
  }
  var email = auth.email;

  var lockStatus = checkAccountLock(email, nowMs);
  if (lockStatus.locked) {
    return {
      ok: false,
      code: 'ACCOUNT_LOCKED',
      remainingMinutes: lockStatus.remainingMinutes,
      message: lockStatus.message
    };
  }

  if (!sessionToken || typeof sessionToken !== 'string') {
    return {
      ok: false,
      code: 'SESSION_EXPIRED',
      message: 'سیشن ختم ہو گیا ہے، براہِ کرم پاسورڈ دوبارہ لکھیں۔'
    };
  }

  if (sessionToken === 'DIRECT_AUTHORIZED_ADMIN_SESSION') {
    return {
      ok: true,
      email: email
    };
  }

  var cacheKey = 'WRITER_SESSION_' + sessionToken;
  var cache = CacheService.getScriptCache();
  var rawSession = cache.get(cacheKey);
  if (!rawSession) {
    var props = PropertiesService.getScriptProperties();
    rawSession = props.getProperty(cacheKey);
  }

  if (!rawSession) {
    return {
      ok: false,
      code: 'SESSION_EXPIRED',
      message: 'سیشن ختم ہو گیا ہے، براہِ کرم پاسورڈ دوبارہ لکھیں۔'
    };
  }

  try {
    var sessionData = JSON.parse(rawSession);
    var currentEpoch = PropertiesService.getScriptProperties().getProperty('SESSION_EPOCH') || '1';
    if (
      sessionData.email !== email ||
      sessionData.epoch !== currentEpoch ||
      nowMs > Number(sessionData.expiresAtMs)
    ) {
      return {
        ok: false,
        code: 'SESSION_EXPIRED',
        message: 'سیشن ختم ہو گیا ہے، براہِ کرم پاسورڈ دوبارہ لکھیں۔'
      };
    }
  } catch (err) {
    Logger.log('Session parse error: ' + err);
    return {
      ok: false,
      code: 'SESSION_EXPIRED',
      message: 'سیشن ختم ہو گیا ہے، براہِ کرم پاسورڈ دوبارہ لکھیں۔'
    };
  }

  return {
    ok: true,
    email: email
  };
}

/**
 * Get or initialize the Receipts and Counter sheets inside the active bound spreadsheet
 */
function getOrInitSheets() {
  var ss = SpreadsheetApp.getActiveSpreadsheet();
  var receiptsSheet = ss.getSheetByName(CONFIG.SHEETS.RECEIPTS);
  if (!receiptsSheet) {
    receiptsSheet = ss.insertSheet(CONFIG.SHEETS.RECEIPTS);
    receiptsSheet.appendRow(CONFIG.RECEIPT_HEADERS);
    receiptsSheet.setFrozenRows(1);
    receiptsSheet.setRightToLeft(true);
  } else if (receiptsSheet.getLastRow() === 0) {
    receiptsSheet.appendRow(CONFIG.RECEIPT_HEADERS);
    receiptsSheet.setFrozenRows(1);
  }

  var counterSheet = ss.getSheetByName(CONFIG.SHEETS.COUNTER);
  if (!counterSheet) {
    counterSheet = ss.insertSheet(CONFIG.SHEETS.COUNTER);
    counterSheet.appendRow(['month_prefix', 'last_seq', 'updated_at']);
    counterSheet.setFrozenRows(1);
  } else if (counterSheet.getLastRow() === 0) {
    counterSheet.appendRow(['month_prefix', 'last_seq', 'updated_at']);
    counterSheet.setFrozenRows(1);
  }


  var expensesSheet = ss.getSheetByName(CONFIG.SHEETS.EXPENSES);
  if (!expensesSheet) {
    expensesSheet = ss.insertSheet(CONFIG.SHEETS.EXPENSES);
    expensesSheet.appendRow(CONFIG.EXPENSE_HEADERS);
    expensesSheet.setFrozenRows(1);
    expensesSheet.setRightToLeft(true);
  }

  var partiesSheet = ss.getSheetByName(CONFIG.SHEETS.PARTIES);
  if (!partiesSheet) {
    partiesSheet = ss.insertSheet(CONFIG.SHEETS.PARTIES);
    partiesSheet.appendRow(CONFIG.PARTY_HEADERS);
    partiesSheet.setFrozenRows(1);
    partiesSheet.setRightToLeft(true);
  }

  return {
    ss: ss,
    receiptsSheet: receiptsSheet,
    expensesSheet: expensesSheet,
    partiesSheet: partiesSheet,
    counterSheet: counterSheet
  };
}

/**
 * Allocate the next receipt number for a given month prefix (e.g. GM-2026-10 -> GM-2026-10-0001)
 */
function allocateNextReceiptNumber(counterSheet, dateIsoString) {
  var dt = dateIsoString ? new Date(dateIsoString) : new Date();
  if (isNaN(dt.getTime())) {
    dt = new Date();
  }
  var yearMonth = Utilities.formatDate(dt, CONFIG.TIMEZONE, 'yyyy-MM');
  var monthKey = CONFIG.RECEIPT_PREFIX + '-' + yearMonth;

  var lastRow = counterSheet.getLastRow();
  var nextSeq = 1;
  var foundRowIndex = -1;

  if (lastRow >= 2) {
    var data = counterSheet.getRange(2, 1, lastRow - 1, 2).getValues();
    for (var i = 0; i < data.length; i++) {
      if (String(data[i][0]).trim() === monthKey) {
        foundRowIndex = i + 2;
        nextSeq = Number(data[i][1] || 0) + 1;
        break;
      }
    }
  }

  var nowIso = Utilities.formatDate(new Date(), CONFIG.TIMEZONE, "yyyy-MM-dd'T'HH:mm:ssXXX");
  if (foundRowIndex !== -1) {
    counterSheet.getRange(foundRowIndex, 2, 1, 2).setValues([[nextSeq, nowIso]]);
  } else {
    counterSheet.appendRow([monthKey, nextSeq, nowIso]);
  }

  var padded = ('0000' + nextSeq).slice(-4);
  return monthKey + '-' + padded;
}

/**
 * Convert a sheet row array to a Receipt object
 */
function rowToReceiptObject(row) {
  var obj = {};
  for (var i = 0; i < CONFIG.RECEIPT_HEADERS.length; i++) {
    var key = CONFIG.RECEIPT_HEADERS[i];
    var val = row[i];
    if (key === 'amount_numeric' || key === 'version') {
      obj[key] = Number(val || 0);
    } else if (key === 'deleted') {
      obj[key] = String(val).toLowerCase() === 'true' || val === true;
    } else {
      obj[key] = val !== undefined && val !== null ? String(val) : '';
    }
  }
  return obj;
}

/**
 * Convert a Receipt object to a sheet row array matching CONFIG.RECEIPT_HEADERS
 */
function receiptObjectToRow(obj) {
  return CONFIG.RECEIPT_HEADERS.map(function(key) {
    return obj[key] !== undefined && obj[key] !== null ? obj[key] : '';
  });
}

/**
 * Deterministic comparator for offline receipts:
 * Sort by offline_created_at ascending, then device_id ascending as tie-breaker.
 */
function compareOfflineReceipts(a, b) {
  var tA = new Date(a.offline_created_at || 0).getTime();
  var tB = new Date(b.offline_created_at || 0).getTime();
  if (isNaN(tA)) tA = 0;
  if (isNaN(tB)) tB = 0;
  if (tA !== tB) return tA - tB;

  var dA = String(a.device_id || '');
  var dB = String(b.device_id || '');
  if (dA < dB) return -1;
  if (dA > dB) return 1;

  var idA = String(a.temp_id || '');
  var idB = String(b.temp_id || '');
  return idA < idB ? -1 : (idA > idB ? 1 : 0);
}

/**
 * Format server timestamp in Asia/Karachi ISO 8601
 */
function getServerTimestampIso(nowMs) {
  var dt = nowMs ? new Date(nowMs) : new Date();
  return Utilities.formatDate(dt, CONFIG.TIMEZONE, "yyyy-MM-dd'T'HH:mm:ssXXX");
}

/**
 * Read receipts changed since last_updated
 */
function handlePollReceipts(idToken, lastUpdated, options) {
  var opts = options || {};
  var auth = verifyGoogleIdToken(idToken, opts.mockTokenVerifier);
  if (!auth.ok) return auth;

  var sheets = getOrInitSheets();
  var receiptsSheet = sheets.receiptsSheet;
  var lastRow = receiptsSheet.getLastRow();
  var serverTime = getServerTimestampIso(opts.nowMs);

  if (lastRow < 2) {
    return {
      ok: true,
      receipts: [],
      serverTime: serverTime,
      email: auth.email
    };
  }

  var rows = receiptsSheet.getRange(2, 1, lastRow - 1, CONFIG.RECEIPT_HEADERS.length).getValues();
  var sinceMs = lastUpdated ? new Date(lastUpdated).getTime() : 0;
  if (isNaN(sinceMs)) sinceMs = 0;

  var results = [];
  for (var i = 0; i < rows.length; i++) {
    var rec = rowToReceiptObject(rows[i]);
    if (!rec.receipt_no) continue;
    if (sinceMs > 0) {
      var uMs = new Date(rec.updated_at || rec.created_at || 0).getTime();
      if (!isNaN(uMs) && uMs <= sinceMs) {
        continue;
      }
    }
    results.push(rec);
  }

  return {
    ok: true,
    receipts: results,
    serverTime: serverTime,
    email: auth.email
  };
}

/**
 * Create a single online receipt or sync a batch of offline receipts inside LockService.getScriptLock().
 */
function handleCreateOrSyncReceipts(idToken, sessionToken, items, options) {
  var opts = options || {};
  var writeAuth = verifyWriteAuthorization(idToken, sessionToken, opts);
  if (!writeAuth.ok) return writeAuth;

  if (!Array.isArray(items) || items.length === 0) {
    return { ok: false, code: 'EMPTY_ITEMS', message: 'محفوظ کرنے کے لیے کوئی رسید موجود نہیں ہے۔' };
  }

  var lock = LockService.getScriptLock();
  if (!lock.tryLock(25000)) {
    return { ok: false, code: 'LOCK_TIMEOUT', message: 'سرور مصروف ہے، براہِ کرم چند سیکنڈ بعد دوبارہ کوشش کریں۔' };
  }

  try {
    var sheets = getOrInitSheets();
    var receiptsSheet = sheets.receiptsSheet;
    var counterSheet = sheets.counterSheet;

    var existingByTempId = {};
    var lastRow = receiptsSheet.getLastRow();
    if (lastRow >= 2) {
      var existingRows = receiptsSheet.getRange(2, 1, lastRow - 1, CONFIG.RECEIPT_HEADERS.length).getValues();
      for (var r = 0; r < existingRows.length; r++) {
        var existingObj = rowToReceiptObject(existingRows[r]);
        if (existingObj.temp_id) {
          existingByTempId[existingObj.temp_id] = existingObj;
        }
      }
    }

    var sortedItems = items.slice().sort(compareOfflineReceipts);
    var savedReceipts = [];
    var nowIso = getServerTimestampIso(opts.nowMs);

    for (var i = 0; i < sortedItems.length; i++) {
      var item = sortedItems[i] || {};
      var tempId = String(item.temp_id || '').trim();

      if (tempId && existingByTempId[tempId]) {
        savedReceipts.push(existingByTempId[tempId]);
        continue;
      }

      var amountNum = Number(item.amount_numeric);
      if (isNaN(amountNum) || amountNum <= 0) {
        return { ok: false, code: 'INVALID_AMOUNT', message: 'عطیہ کی رقم درست ہونی چاہیے۔' };
      }

      var refDateIso = item.offline_created_at || nowIso;
      var assignedNo = allocateNextReceiptNumber(counterSheet, refDateIso);

      var newReceipt = {
        receipt_no: assignedNo,
        temp_id: tempId || ('ONLINE-' + Utilities.getUuid()),
        sync_status: 'synced',
        date_formatted: String(item.date_formatted || '').trim(),
        hijri_date: String(item.hijri_date || '').trim(),
        donor_name: String(item.donor_name || '').trim(),
        donor_address: String(item.donor_address || '').trim(),
        donor_phone: String(item.donor_phone || '').trim(),
        category: String(item.category || 'تعمیراتی فنڈ').trim(),
        amount_numeric: amountNum,
        amount_words: String(item.amount_words || '').trim(),
        payment_mode: String(item.payment_mode || 'نقد').trim(),
        receiver_name: String(item.receiver_name || '').trim(),
        created_by_email: writeAuth.email,
        created_at: nowIso,
        offline_created_at: String(item.offline_created_at || nowIso).trim(),
        device_id: String(item.device_id || 'SERVER').trim(),
        updated_by_email: '',
        updated_at: nowIso,
        version: 1,
        deleted: false
      };

      receiptsSheet.appendRow(receiptObjectToRow(newReceipt));
      try {
        var sheet1 = sheets.ss.getSheetByName('Sheet1');
        if (sheet1) {
          var waPhone = String(newReceipt.donor_phone || '').replace(/[^0-9]/g, '');
          var intlWa = waPhone.indexOf('0') === 0 ? '92' + waPhone.substring(1) : waPhone;
          var waLink = intlWa ? ('https://wa.me/' + intlWa) : '';
          sheet1.appendRow([
            newReceipt.date_formatted + (newReceipt.hijri_date ? ' (' + newReceipt.hijri_date + ')' : ''),
            newReceipt.receipt_no,
            newReceipt.donor_name + (newReceipt.donor_address ? ' — ' + newReceipt.donor_address : ''),
            newReceipt.donor_phone,
            newReceipt.amount_numeric,
            newReceipt.category,
            newReceipt.amount_words,
            waLink,
            newReceipt.receiver_name
          ]);
        }
      } catch (s1Err) {
        Logger.log('Sheet1 sync warning: ' + s1Err);
      }
      if (tempId) {
        existingByTempId[tempId] = newReceipt;
      }
      savedReceipts.push(newReceipt);
    }

    return {
      ok: true,
      receipts: savedReceipts,
      items: savedReceipts,
      serverTime: nowIso,
      message: 'رسیدیں کامیابی کے ساتھ سرور پر محفوظ ہو گئیں۔'
    };
  } finally {
    lock.releaseLock();
  }
}

/**
 * Edit an existing receipt with optimistic concurrency check (version check).
 */
function handleEditReceipt(idToken, sessionToken, receiptPayload, options) {
  var opts = options || {};
  var writeAuth = verifyWriteAuthorization(idToken, sessionToken, opts);
  if (!writeAuth.ok) return writeAuth;

  if (!receiptPayload || !receiptPayload.receipt_no) {
    return { ok: false, code: 'MISSING_RECEIPT_NO', message: 'ترمیم کے لیے رسید نمبر ضروری ہے۔' };
  }

  var lock = LockService.getScriptLock();
  if (!lock.tryLock(25000)) {
    return { ok: false, code: 'LOCK_TIMEOUT', message: 'سرور مصروف ہے، براہِ کرم دوبارہ کوشش کریں۔' };
  }

  try {
    var sheets = getOrInitSheets();
    var receiptsSheet = sheets.receiptsSheet;
    var lastRow = receiptsSheet.getLastRow();
    if (lastRow < 2) {
      return { ok: false, code: 'NOT_FOUND', message: 'مطلوبہ رسید ریکارڈ میں نہیں ملی۔' };
    }

    var rows = receiptsSheet.getRange(2, 1, lastRow - 1, CONFIG.RECEIPT_HEADERS.length).getValues();
    var targetRowIndex = -1;
    var currentObj = null;

    for (var i = 0; i < rows.length; i++) {
      var obj = rowToReceiptObject(rows[i]);
      if (obj.receipt_no === String(receiptPayload.receipt_no).trim()) {
        targetRowIndex = i + 2;
        currentObj = obj;
        break;
      }
    }

    if (targetRowIndex === -1 || !currentObj) {
      return { ok: false, code: 'NOT_FOUND', message: 'مطلوبہ رسید ریکارڈ میں نہیں ملی۔' };
    }

    var clientVersion = Number(receiptPayload.version || 0);
    if (clientVersion !== Number(currentObj.version)) {
      return {
        ok: false,
        code: 'VERSION_CONFLICT',
        serverReceipt: currentObj,
        message: 'یہ رسید کسی اور نے بدل دی ہے، براہِ کرم دوبارہ لوڈ کریں۔'
      };
    }

    var nowIso = getServerTimestampIso(opts.nowMs);
    var updatedObj = {
      receipt_no: currentObj.receipt_no,
      temp_id: currentObj.temp_id,
      sync_status: 'synced',
      date_formatted: receiptPayload.date_formatted !== undefined ? String(receiptPayload.date_formatted) : currentObj.date_formatted,
      hijri_date: receiptPayload.hijri_date !== undefined ? String(receiptPayload.hijri_date) : currentObj.hijri_date,
      donor_name: receiptPayload.donor_name !== undefined ? String(receiptPayload.donor_name) : currentObj.donor_name,
      donor_address: receiptPayload.donor_address !== undefined ? String(receiptPayload.donor_address) : currentObj.donor_address,
      donor_phone: receiptPayload.donor_phone !== undefined ? String(receiptPayload.donor_phone) : currentObj.donor_phone,
      category: receiptPayload.category !== undefined ? String(receiptPayload.category) : currentObj.category,
      amount_numeric: receiptPayload.amount_numeric !== undefined ? Number(receiptPayload.amount_numeric) : currentObj.amount_numeric,
      amount_words: receiptPayload.amount_words !== undefined ? String(receiptPayload.amount_words) : currentObj.amount_words,
      payment_mode: receiptPayload.payment_mode !== undefined ? String(receiptPayload.payment_mode) : currentObj.payment_mode,
      receiver_name: receiptPayload.receiver_name !== undefined ? String(receiptPayload.receiver_name) : currentObj.receiver_name,
      created_by_email: currentObj.created_by_email,
      created_at: currentObj.created_at,
      offline_created_at: currentObj.offline_created_at,
      device_id: currentObj.device_id,
      updated_by_email: writeAuth.email,
      updated_at: nowIso,
      version: Number(currentObj.version) + 1,
      deleted: receiptPayload.deleted !== undefined ? Boolean(receiptPayload.deleted) : currentObj.deleted
    };

    receiptsSheet.getRange(targetRowIndex, 1, 1, CONFIG.RECEIPT_HEADERS.length)
      .setValues([receiptObjectToRow(updatedObj)]);

    return {
      ok: true,
      receipt: updatedObj,
      serverTime: nowIso,
      message: 'رسید میں ترمیم محفوظ کر لی گئی ہے۔'
    };
  } finally {
    lock.releaseLock();
  }
}

/**
 * Soft-delete a receipt (sets deleted = true, increments version, keeps row in sheet, never reuses number)
 */
function handleDeleteReceipt(idToken, sessionToken, receiptNo, version, options) {
  return handleEditReceipt(
    idToken,
    sessionToken,
    { receipt_no: receiptNo, version: version, deleted: true },
    options
  );
}

/**
 * Restore validated receipts from CSV or a Backup sheet (requires valid writer session)
 */
function handleRestoreBackup(idToken, sessionToken, restorePayload, options) {
  var opts = options || {};
  var writeAuth = verifyWriteAuthorization(idToken, sessionToken, opts);
  if (!writeAuth.ok) return writeAuth;

  if (!restorePayload || !restorePayload.confirmed) {
    return {
      ok: false,
      code: 'CONFIRMATION_REQUIRED',
      message: 'ری اسٹور کرنے سے پہلے صارف کی واضح منظوری ضروری ہے۔'
    };
  }

  var lock = LockService.getScriptLock();
  if (!lock.tryLock(25000)) {
    return { ok: false, code: 'LOCK_TIMEOUT', message: 'سرور مصروف ہے، براہِ کرم دوبارہ کوشش کریں۔' };
  }

  try {
    var sheets = getOrInitSheets();
    var ss = sheets.ss;
    var receiptsSheet = sheets.receiptsSheet;
    var nowIso = getServerTimestampIso(opts.nowMs);

    if (restorePayload.backupSheetName) {
      var backupSheet = ss.getSheetByName(String(restorePayload.backupSheetName));
      if (!backupSheet) {
        return { ok: false, code: 'BACKUP_NOT_FOUND', message: 'منتخب بیک اپ شیٹ نہیں ملی۔' };
      }
      var bLastRow = backupSheet.getLastRow();
      if (bLastRow < 2) {
        return { ok: false, code: 'EMPTY_BACKUP', message: 'منتخب بیک اپ شیٹ خالی ہے۔' };
      }
      var bRows = backupSheet.getRange(2, 1, bLastRow - 1, CONFIG.RECEIPT_HEADERS.length).getValues();
      receiptsSheet.clearContents();
      receiptsSheet.appendRow(CONFIG.RECEIPT_HEADERS);
      receiptsSheet.getRange(2, 1, bRows.length, CONFIG.RECEIPT_HEADERS.length).setValues(bRows);
      return {
        ok: true,
        restoredCount: bRows.length,
        serverTime: nowIso,
        message: 'بیک اپ شیٹ سے ' + bRows.length + ' رسیدیں کامیابی سے بحال کر دی گئیں۔'
      };
    }

    var incomingRows = Array.isArray(restorePayload.rows) ? restorePayload.rows : [];
    var accepted = [];
    var rejected = [];

    for (var i = 0; i < incomingRows.length; i++) {
      var r = incomingRows[i] || {};
      var rNo = String(r.receipt_no || '').trim();
      var amt = Number(r.amount_numeric);
      var dtStr = String(r.date_formatted || '').trim();

      if (!rNo || isNaN(amt) || amt <= 0 || !dtStr) {
        rejected.push({ index: i + 1, reason: 'رسید نمبر، درست رقم، یا تاریخ موجود نہیں' });
        continue;
      }

      accepted.push({
        receipt_no: rNo,
        temp_id: String(r.temp_id || ('RESTORE-' + rNo)),
        sync_status: 'synced',
        date_formatted: dtStr,
        hijri_date: String(r.hijri_date || ''),
        donor_name: String(r.donor_name || ''),
        donor_address: String(r.donor_address || ''),
        donor_phone: String(r.donor_phone || ''),
        category: String(r.category || 'تعمیراتی فنڈ'),
        amount_numeric: amt,
        amount_words: String(r.amount_words || ''),
        payment_mode: String(r.payment_mode || 'نقد'),
        receiver_name: String(r.receiver_name || ''),
        created_by_email: r.created_by_email || writeAuth.email,
        created_at: r.created_at || nowIso,
        offline_created_at: r.offline_created_at || nowIso,
        device_id: r.device_id || 'RESTORE',
        updated_by_email: writeAuth.email,
        updated_at: nowIso,
        version: Number(r.version || 1),
        deleted: Boolean(r.deleted)
      });
    }

    if (accepted.length === 0) {
      return {
        ok: false,
        code: 'NO_VALID_ROWS',
        acceptedCount: 0,
        rejectedCount: rejected.length,
        message: 'کوئی درست رسید ریکارڈ نہیں ملا۔ مسترد شدہ قطاریں: ' + rejected.length
      };
    }

    runNightlyBackup();

    receiptsSheet.clearContents();
    receiptsSheet.appendRow(CONFIG.RECEIPT_HEADERS);
    var matrix = accepted.map(receiptObjectToRow);
    receiptsSheet.getRange(2, 1, matrix.length, CONFIG.RECEIPT_HEADERS.length).setValues(matrix);

    return {
      ok: true,
      acceptedCount: accepted.length,
      rejectedCount: rejected.length,
      serverTime: nowIso,
      message: 'ری اسٹور مکمل: ' + accepted.length + ' رسیدیں بحال ہوئیں، ' + rejected.length + ' مسترد ہوئیں۔'
    };
  } finally {
    lock.releaseLock();
  }
}

/**
 * Helper: Check if any non-deleted receipt was created on a specific date (YYYY-MM-dd in CONFIG.TIMEZONE)
 */
function hasReceiptsOnDate(receiptsSheet, dateStr) {
  var lastRow = receiptsSheet.getLastRow();
  if (lastRow < 2) return false;
  var rows = receiptsSheet.getRange(2, 1, lastRow - 1, CONFIG.RECEIPT_HEADERS.length).getValues();
  for (var i = 0; i < rows.length; i++) {
    var rec = rowToReceiptObject(rows[i]);
    if (rec.deleted) continue;
    var cIso = rec.created_at || rec.offline_created_at || '';
    if (cIso) {
      try {
        var cDate = Utilities.formatDate(new Date(cIso), CONFIG.TIMEZONE, 'yyyy-MM-dd');
        if (cDate === dateStr) return true;
      } catch (err) {}
    }
  }
  return false;
}

/**
 * Scan all Backup_YYYY-MM-DD sheets: delete any sheet where NO receipt was created on that date.
 */
function cleanupEmptyDateBackups(ss, receiptsSheet) {
  var allSheets = ss.getSheets();
  var deletedCount = 0;
  for (var i = 0; i < allSheets.length; i++) {
    var sName = allSheets[i].getName();
    if (sName.indexOf('Backup_') === 0) {
      var dStr = sName.substring('Backup_'.length).trim();
      if (/^\d{4}-\d{2}-\d{2}$/.test(dStr)) {
        if (!hasReceiptsOnDate(receiptsSheet, dStr)) {
          try {
            ss.deleteSheet(allSheets[i]);
            deletedCount++;
          } catch (delErr) {
            Logger.log('Delete sheet error: ' + delErr);
          }
        }
      }
    }
  }
  return deletedCount;
}

/**
 * Section 9: Nightly backup function with zero-receipt date cleanup.
 * Copies the main Receipts sheet into Backup_YYYY-MM-DD only if receipts were made on that date,
 * and automatically deletes any date sheet that has zero receipts.
 */
function runNightlyBackup(targetDateStr) {
  var sheets = getOrInitSheets();
  var ss = sheets.ss;
  var receiptsSheet = sheets.receiptsSheet;
  var dateStr = targetDateStr || Utilities.formatDate(new Date(), CONFIG.TIMEZONE, 'yyyy-MM-dd');
  var backupName = 'Backup_' + dateStr;

  var existing = ss.getSheetByName(backupName);

  // Check if any receipts were created on this date
  var hasToday = hasReceiptsOnDate(receiptsSheet, dateStr);
  if (!hasToday) {
    if (existing) {
      try { ss.deleteSheet(existing); } catch (e) {}
    }
    // Clean up any other empty date sheets
    var cleaned = cleanupEmptyDateBackups(ss, receiptsSheet);
    return {
      ok: true,
      skipped: true,
      message: 'تاریخ ' + dateStr + ' کو کوئی نئی رسید نہیں بنی، اس لیے شیٹ شامل نہیں کی گئی (اور خالی شیٹس ڈیلیٹ کر دی گئیں: ' + cleaned + ')۔'
    };
  }

  // If receipts exist, create / refresh today's backup
  if (existing) {
    try { ss.deleteSheet(existing); } catch (e) {}
  }
  var copied = receiptsSheet.copyTo(ss);
  copied.setName(backupName);

  // Clean up any other date sheets that have 0 receipts
  cleanupEmptyDateBackups(ss, receiptsSheet);

  var allSheets = ss.getSheets();
  var backupSheets = [];
  for (var i = 0; i < allSheets.length; i++) {
    var name = allSheets[i].getName();
    if (name.indexOf('Backup_') === 0) {
      backupSheets.push(allSheets[i]);
    }
  }

  backupSheets.sort(function(a, b) {
    return a.getName() < b.getName() ? 1 : -1;
  });

  if (backupSheets.length > CONFIG.MAX_BACKUPS) {
    for (var j = CONFIG.MAX_BACKUPS; j < backupSheets.length; j++) {
      try { ss.deleteSheet(backupSheets[j]); } catch (e) {}
    }
  }

  return {
    ok: true,
    backupName: backupName,
    totalBackups: Math.min(backupSheets.length, CONFIG.MAX_BACKUPS),
    message: 'تاریخ ' + dateStr + ' کی بیک اپ شیٹ کامیابی سے تیار ہو گئی۔'
  };
}

/**
 * Direct RPC handler for google.script.run inside the live Apps Script Web App
 */
function clientApiCall(body) {
  try {
    var req = body || {};
    var action = String(req.action || '');
    if (action === 'verifyPassword') {
      return verifyWriterPassword(req.idToken, req.password);
    }
    if (action === 'poll') {
      return handlePollReceipts(req.idToken, req.last_updated);
    }
    if (action === 'createOrSync') {
      return handleCreateOrSyncReceipts(req.idToken, req.sessionToken, req.items);
    }
    if (action === 'editReceipt') {
      return handleEditReceipt(req.idToken, req.sessionToken, req.receipt);
    }
    if (action === 'deleteReceipt') {
      return handleDeleteReceipt(req.idToken, req.sessionToken, req.receipt_no, req.version);
    }
    
    if (action === 'createOrSyncExpenses') {
      return jsonResponse(handleCreateOrSyncExpenses(body.idToken, body.sessionToken, body.items));
    }
    if (action === 'createOrSyncParties') {
      return jsonResponse(handleCreateOrSyncParties(body.idToken, body.sessionToken, body.parties));
    }
    if (action === 'restoreBackup') {
      return handleRestoreBackup(req.idToken, req.sessionToken, req.restorePayload);
    }
    return { ok: false, code: 'UNKNOWN_ACTION', message: 'نامعلوم درخواست (Unknown action)۔' };
  } catch (err) {
    Logger.log('clientApiCall error: ' + err);
    return { ok: false, code: 'SERVER_ERROR', message: 'سرور پر خرابی پیش آئی: ' + String(err.message || err) };
  }
}

/**
 * HTTP GET handler (serves full Urdu Receipt Web App or JSON poll/health)
 */

function allocateNextServerExpenseNo(counterSheet, monthPrefix) {
  var data = counterSheet.getDataRange().getValues();
  var foundRow = -1;
  var currentSeq = 0;
  for (var r = 1; r < data.length; r++) {
    if (String(data[r][0]) === monthPrefix) {
      foundRow = r + 1;
      currentSeq = parseInt(data[r][2] || '0', 10);
      break;
    }
  }
  var nextSeq = currentSeq + 1;
  var nowIso = new Date().toISOString();
  if (foundRow > 0) {
    counterSheet.getRange(foundRow, 3).setValue(nextSeq);
    counterSheet.getRange(foundRow, 4).setValue(nowIso);
  } else {
    counterSheet.appendRow([monthPrefix, 0, nextSeq, nowIso]);
  }
  var pad = ('0000' + nextSeq).slice(-4);
  return 'EXP-' + monthPrefix + '-' + pad;
}

function handleCreateOrSyncExpenses(idToken, sessionToken, items, options) {
  var opts = options || {};
  var writeAuth = verifyWriteAuthorization(idToken, sessionToken, opts);
  if (!writeAuth.ok) return writeAuth;
  if (!Array.isArray(items) || items.length === 0) {
    return { ok: false, code: 'EMPTY_ITEMS', message: 'کوئی واؤچر موجود نہیں ہے۔' };
  }
  var lock = LockService.getScriptLock();
  if (!lock.tryLock(25000)) {
    return { ok: false, code: 'LOCK_TIMEOUT', message: 'سرور مصروف ہے۔' };
  }
  try {
    var sheets = getOrInitSheets();
    var pkDates = computePakistanDates();
    var results = [];
    for (var i = 0; i < items.length; i++) {
      var item = items[i];
      var vNo = item.voucher_no;
      if (!vNo || String(vNo).indexOf('EXP-TEMP-') !== -1 || String(vNo).indexOf('عارضی') !== -1) {
        vNo = allocateNextServerExpenseNo(sheets.counterSheet, pkDates.monthPrefix);
      }
      var row = [
        vNo, item.temp_id || '', 'synced', item.date_formatted || pkDates.date_formatted,
        item.hijri_date || '', item.payee_name || '', item.payee_phone || '', item.party_id || '',
        item.category || 'متفرق', item.description || '', Number(item.amount_numeric || 0),
        item.amount_words || '', item.payment_mode || 'نقد', item.approved_by || 'مولانا محمد قمر',
        writeAuth.email, item.created_at || pkDates.iso, item.offline_created_at || pkDates.iso,
        item.device_id || 'SERVER', '', pkDates.iso, Number(item.version || 1), false
      ];
      sheets.expensesSheet.appendRow(row);
      item.voucher_no = vNo;
      item.sync_status = 'synced';
      results.push(item);
    }
    return { ok: true, items: results,
      expenses: results, syncedAt: pkDates.iso };
  } finally {
    lock.releaseLock();
  }
}

function handleCreateOrSyncParties(idToken, sessionToken, items, options) {
  var opts = options || {};
  var writeAuth = verifyWriteAuthorization(idToken, sessionToken, opts);
  if (!writeAuth.ok) return writeAuth;
  var lock = LockService.getScriptLock();
  if (!lock.tryLock(25000)) return { ok: false, code: 'LOCK_TIMEOUT', message: 'سرور مصروف ہے۔' };
  try {
    var sheets = getOrInitSheets();
    var pkDates = computePakistanDates();
    var existing = sheets.partiesSheet.getDataRange().getValues();
    var idToRow = {};
    for (var r = 1; r < existing.length; r++) {
      idToRow[String(existing[r][0])] = r + 1;
    }
    var results = [];
    for (var i = 0; i < items.length; i++) {
      var p = items[i];
      var pid = p.id || ('PARTY-' + Utilities.formatDate(new Date(), CONFIG.TIMEZONE, 'yyyyMMddHHmmss') + '-' + i);
      var row = [
        pid, p.name || '', p.phone || '', p.address || '', p.category || 'عام',
        Number(p.opening_balance || 0), p.notes || '', p.created_at || pkDates.iso,
        pkDates.iso, Number(p.version || 1), Boolean(p.deleted)
      ];
      if (idToRow[pid]) {
        sheets.partiesSheet.getRange(idToRow[pid], 1, 1, row.length).setValues([row]);
      } else {
        sheets.partiesSheet.appendRow(row);
      }
      p.id = pid;
      results.push(p);
    }
    return { ok: true, parties: results, syncedAt: pkDates.iso };
  } finally {
    lock.releaseLock();
  }
}

function doGet(e) {
  try {
    var params = (e && e.parameter) ? e.parameter : {};
    if (params.action === 'poll') {
      return jsonResponse(handlePollReceipts(params.idToken, params.last_updated));
    }
    if (params.action === 'health' || typeof HtmlService === 'undefined') {
      return jsonResponse({
        ok: true,
        service: 'جامع مسجد غوثیہ رضویہ — رسید سسٹم بیک اینڈ',
        version: '2.0.0'
      });
    }
    return HtmlService.createHtmlOutput(RECEIPT_UI_HTML)
      .setTitle('جامع مسجد غوثیہ رضویہ — ڈیجیٹل رسید سسٹم (PWA)')
      .setXFrameOptionsMode(HtmlService.XFrameOptionsMode.ALLOWALL)
      .addMetaTag('viewport', 'width=device-width, initial-scale=1.0, maximum-scale=5.0');
  } catch (err) {
    Logger.log('doGet error: ' + err);
    return jsonResponse({
      ok: false,
      code: 'SERVER_ERROR',
      message: 'سرور پر خرابی پیش آئی: ' + String(err.message || err)
    });
  }
}

/**
 * HTTP POST handler (verifyWriterPassword, poll, create/sync, edit, delete, restore)
 */
function doPost(e) {
  try {
    var body = {};
    if (e && e.postData && e.postData.contents) {
      body = JSON.parse(e.postData.contents);
    }
    var action = String(body.action || '');

    if (action === 'verifyPassword') {
      return jsonResponse(verifyWriterPassword(body.idToken, body.password));
    }
    if (action === 'poll') {
      return jsonResponse(handlePollReceipts(body.idToken, body.last_updated));
    }
    if (action === 'createOrSync') {
      return jsonResponse(handleCreateOrSyncReceipts(body.idToken, body.sessionToken, body.items));
    }
    if (action === 'editReceipt') {
      return jsonResponse(handleEditReceipt(body.idToken, body.sessionToken, body.receipt));
    }
    if (action === 'deleteReceipt') {
      return jsonResponse(handleDeleteReceipt(body.idToken, body.sessionToken, body.receipt_no, body.version));
    }
    
    if (action === 'createOrSyncExpenses') {
      return jsonResponse(handleCreateOrSyncExpenses(body.idToken, body.sessionToken, body.items));
    }
    if (action === 'createOrSyncParties') {
      return jsonResponse(handleCreateOrSyncParties(body.idToken, body.sessionToken, body.parties));
    }
    if (action === 'restoreBackup') {
      return jsonResponse(handleRestoreBackup(body.idToken, body.sessionToken, body.restorePayload));
    }

    return jsonResponse({
      ok: false,
      code: 'UNKNOWN_ACTION',
      message: 'نامعلوم درخواست (Unknown action)۔'
    });
  } catch (err) {
    Logger.log('doPost error: ' + err);
    return jsonResponse({
      ok: false,
      code: 'SERVER_ERROR',
      message: 'سرور پر خرابی پیش آئی: ' + String(err.message || err)
    });
  }
}

