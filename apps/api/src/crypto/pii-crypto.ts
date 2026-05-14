import {
  createCipheriv,
  createDecipheriv,
  createHmac,
  randomBytes,
} from 'crypto';

// Šifrēšanas atslēgu kešs — izvairāmies no atkārtota hex parsēšanas
let _encKey: Buffer | null = null;
let _idxKey: Buffer | null = null;

/**
 * Iegūt šifrēšanas atslēgu no vides mainīgā.
 * Kešo atmiņā — atslēga nemainās runtime laikā.
 */
function getEncryptionKey(): Buffer {
  if (_encKey) return _encKey;
  const hex = process.env.PII_ENCRYPTION_KEY ?? '';
  if (hex.length !== 64) {
    throw new Error(
      'PII_ENCRYPTION_KEY jābūt 32-baitu hex virknei (64 simboli)',
    );
  }
  _encKey = Buffer.from(hex, 'hex');
  return _encKey;
}

/**
 * Iegūt blind index atslēgu no vides mainīgā.
 * Atsevišķa atslēga no šifrēšanas — OWASP ASVS v5.0 §14.2
 */
function getBlindIndexKey(): Buffer {
  if (_idxKey) return _idxKey;
  const hex = process.env.PII_BLIND_INDEX_KEY ?? '';
  if (hex.length !== 64) {
    throw new Error(
      'PII_BLIND_INDEX_KEY jābūt 32-baitu hex virknei (64 simboli)',
    );
  }
  _idxKey = Buffer.from(hex, 'hex');
  return _idxKey;
}

/**
 * Šifrē vienu lauka vērtību ar AES-256-GCM.
 * Formāts: base64url(IV[12] + authTag[16] + ciphertext)
 * Katram ierakstam jauns IV — novērš pattern analīzi.
 */
export function encryptField(plaintext: string): string {
  const key = getEncryptionKey();
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([
    cipher.update(plaintext, 'utf8'),
    cipher.final(),
  ]);
  const tag = cipher.getAuthTag();
  // IV + tag + ciphertext — tāds pats formāts kā TOTP šifrēšanā
  return Buffer.concat([iv, tag, encrypted]).toString('base64url');
}

/**
 * Atšifrē vienu lauka vērtību.
 * Izmet kļūdu ja vērtība nav derīga šifrētā formātā.
 */
export function decryptField(ciphertext: string): string {
  const key = getEncryptionKey();
  const buf = Buffer.from(ciphertext, 'base64url');
  if (buf.length < 28) {
    // Pārāk īss lai būtu šifrēts — iespējams plaintext no vecā formāta
    throw new Error('Nederīgs šifrētais teksts — par īsu');
  }
  const iv = buf.subarray(0, 12);
  const tag = buf.subarray(12, 28);
  const encrypted = buf.subarray(28);
  const decipher = createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  return decipher.update(encrypted).toString('utf8') + decipher.final('utf8');
}

/**
 * Aprēķina HMAC-SHA256 blind index meklēšanai.
 * Normalizē ievadi pirms HMAC — e-pasts vienmēr lowercase + trim.
 * Atsevišķa atslēga no šifrēšanas — kompromitējot vienu, otra paliek droša.
 */
export function blindIndex(value: string): string {
  const key = getBlindIndexKey();
  return createHmac('sha256', key)
    .update(value.toLowerCase().trim())
    .digest('base64url');
}

/**
 * Pārbauda vai vērtība izskatās kā šifrēts lauks.
 * Nepieciešams migrācijas laikā — vecās rindas var būt plaintext.
 */
export function isEncryptedValue(value: string): boolean {
  try {
    const buf = Buffer.from(value, 'base64url');
    // Šifrēts lauks: vismaz IV(12) + tag(16) + 1 baits
    return buf.length >= 29 && value !== buf.toString('utf8');
  } catch {
    return false;
  }
}

/**
 * Atslēgu kešu notīrīšana — tikai testiem.
 */
export function _resetKeyCache(): void {
  _encKey = null;
  _idxKey = null;
}
