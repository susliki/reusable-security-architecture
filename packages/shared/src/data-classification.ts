/*
  Datu klasifikācijas matrica — nosaka aizsardzības līmeni katram datu laukam.
 
 Klasifikācijas līmeņi (augošā secībā):
    PUBLIC       — publiski pieejami dati
    INTERNAL     — iekšējie darbības dati (statusi, piešķīrumi)
    CONFIDENTIAL — sensitīvi personas dati (profili, kontaktinfo)
    RESTRICTED   — īpaši aizsargāti dati (personas kods, autentifikācijas noslēpumi)
 
  Izmantojums:
    - Šifrēšana at-rest: RESTRICTED lauki tiek šifrēti ar AES-256-GCM
    - Audita žurnāls: RESTRICTED/CONFIDENTIAL lauki tiek maskēti
    - Eksporti: RESTRICTED lauki tiek izslēgti vai maskēti
    - Piekļuves kontrole: augstāks līmenis = stingrāki nosacījumi
 
  Atsauces:
    GDPR 9. pants — īpašo kategoriju dati
    OWASP ASVS v5 §8.3 — sensitīvu datu aizsardzība
 */

export type DataClassification = 'PUBLIC' | 'INTERNAL' | 'CONFIDENTIAL' | 'RESTRICTED';

/** Klasifikācijas līmeņu hierarhija (augstāks skaitlis = stingrāka aizsardzība) */
export const CLASSIFICATION_LEVEL: Record<DataClassification, number> = {
  PUBLIC: 0,
  INTERNAL: 1,
  CONFIDENTIAL: 2,
  RESTRICTED: 3,
};

/** Vai klasifikācija prasa šifrēšanu at-rest */
export function requiresEncryption(c: DataClassification): boolean {
  return c === 'RESTRICTED';
}

/** Vai klasifikācija prasa maskēšanu audita žurnālā */
export function requiresAuditMasking(c: DataClassification): boolean {
  return c === 'RESTRICTED' || c === 'CONFIDENTIAL';
}

/** Vai klasifikācija ir iekļaujama eksportā bez maskēšanas */
export function allowedInExport(c: DataClassification): boolean {
  return c === 'PUBLIC' || c === 'INTERNAL';
}

/**
 * Viena lauka klasifikācijas ieraksts.
 */
export interface FieldClassification {
  model: string;
  field: string;
  classification: DataClassification;
  /** Pamatojums — GDPR pants, OWASP atsauce vai biznesa pamatojums */
  rationale: string;
}

// ── RESTRICTED ──
const RESTRICTED_FIELDS: FieldClassification[] = [
  { model: 'Identity', field: 'secret', classification: 'RESTRICTED', rationale: 'TOTP noslēpums (OWASP ASVS §2.8)' },
  { model: 'Identity', field: 'providerId', classification: 'RESTRICTED', rationale: 'Ārējais identifikators — var saturēt personas kodu' },
  { model: 'PasskeyCredential', field: 'publicKey', classification: 'RESTRICTED', rationale: 'WebAuthn publiskā atslēga' },
  { model: 'PasskeyCredential', field: 'credentialId', classification: 'RESTRICTED', rationale: 'WebAuthn credential ID' },
  { model: 'User', field: 'email', classification: 'RESTRICTED', rationale: 'GDPR 4(1) — identifikācijas līdzeklis' },
  { model: 'User', field: 'personalCodeEnc', classification: 'RESTRICTED', rationale: 'Nacionālais personas kods (GDPR 87. pants)' },
  { model: 'User', field: 'idCodeHmac', classification: 'RESTRICTED', rationale: 'Blind index personas kodam' },
  { model: 'AuditLog', field: 'prevHash', classification: 'RESTRICTED', rationale: 'HMAC ķēdes integritātes signāls' },
  { model: 'AuditLog', field: 'hash', classification: 'RESTRICTED', rationale: 'HMAC ķēdes integritātes signāls' },
];

// ── CONFIDENTIAL ──
const CONFIDENTIAL_FIELDS: FieldClassification[] = [
  { model: 'User', field: 'firstName', classification: 'CONFIDENTIAL', rationale: 'GDPR 4(1) — personas dati' },
  { model: 'User', field: 'lastName', classification: 'CONFIDENTIAL', rationale: 'GDPR 4(1) — personas dati' },
  { model: 'User', field: 'phone', classification: 'CONFIDENTIAL', rationale: 'Kontaktinformācija' },
  { model: 'User', field: 'address', classification: 'CONFIDENTIAL', rationale: 'Dzīvesvietas informācija' },
  { model: 'User', field: 'dateOfBirth', classification: 'CONFIDENTIAL', rationale: 'Personas dati' },
  { model: 'User', field: 'birthPlace', classification: 'CONFIDENTIAL', rationale: 'Personas dati' },
  { model: 'User', field: 'citizenship', classification: 'CONFIDENTIAL', rationale: 'Pilsonība — GDPR 9. pants saistīts' },
  { model: 'User', field: 'sex', classification: 'CONFIDENTIAL', rationale: 'Dzimums — GDPR 9. pants' },
  { model: 'UserNameHistory', field: 'previousFirst', classification: 'CONFIDENTIAL', rationale: 'Iepriekšējie personas dati' },
  { model: 'UserNameHistory', field: 'previousLast', classification: 'CONFIDENTIAL', rationale: 'Iepriekšējie personas dati' },
  { model: 'UserNameHistory', field: 'newFirst', classification: 'CONFIDENTIAL', rationale: 'Personas dati' },
  { model: 'UserNameHistory', field: 'newLast', classification: 'CONFIDENTIAL', rationale: 'Personas dati' },
  { model: 'VerificationDocument', field: 'storageKey', classification: 'CONFIDENTIAL', rationale: 'Personas dokumenta atslēga objektu krātuvē' },
];

// ── INTERNAL ──
const INTERNAL_FIELDS: FieldClassification[] = [
  { model: 'User', field: 'role', classification: 'INTERNAL', rationale: 'Lietotāja loma sistēmā' },
  { model: 'User', field: 'status', classification: 'INTERNAL', rationale: 'Konta statuss' },
  { model: 'User', field: 'entraRole', classification: 'INTERNAL', rationale: 'Entra apakšloma' },
  { model: 'User', field: 'lastLoginAt', classification: 'INTERNAL', rationale: 'Pēdējās aktivitātes laiks' },
  { model: 'User', field: 'identityVerifiedAt', classification: 'INTERNAL', rationale: 'Verifikācijas laiks' },
  { model: 'User', field: 'identityVerifiedBy', classification: 'INTERNAL', rationale: 'Verifikācijas autors' },
  { model: 'User', field: 'verificationMethod', classification: 'INTERNAL', rationale: 'Verifikācijas metode' },
  { model: 'Session', field: 'expiresAt', classification: 'INTERNAL', rationale: 'Sesijas dzīves cikls' },
  { model: 'AuditLog', field: 'action', classification: 'INTERNAL', rationale: 'Audita darbības tips' },
  { model: 'AuditLog', field: 'result', classification: 'INTERNAL', rationale: 'Darbības rezultāts' },
  { model: 'AuditLog', field: 'subjectId', classification: 'INTERNAL', rationale: 'Aktora ID auditā' },
  { model: 'AuditLog', field: 'entityType', classification: 'INTERNAL', rationale: 'Audita objekta tips' },
  { model: 'AuditLog', field: 'entityId', classification: 'INTERNAL', rationale: 'Audita objekta ID' },
];

// ── PUBLIC ──
const PUBLIC_FIELDS: FieldClassification[] = [
  { model: 'User', field: 'id', classification: 'PUBLIC', rationale: 'Iekšējais UUID — neidentificē personu ārpus sistēmas' },
  { model: 'User', field: 'createdAt', classification: 'PUBLIC', rationale: 'Konta izveides laiks' },
  { model: 'Notification', field: 'type', classification: 'PUBLIC', rationale: 'Paziņojuma kategorija' },
  { model: 'Notification', field: 'createdAt', classification: 'PUBLIC', rationale: 'Paziņojuma laiks' },
];

// ── Apvienotā karte ──
export const FIELD_CLASSIFICATIONS: FieldClassification[] = [
  ...RESTRICTED_FIELDS,
  ...CONFIDENTIAL_FIELDS,
  ...INTERNAL_FIELDS,
  ...PUBLIC_FIELDS,
];

// ── Palīgfunkcijas ──

/** Iegūst lauka klasifikāciju vai INTERNAL kā default */
export function getFieldClassification(model: string, field: string): DataClassification {
  const entry = FIELD_CLASSIFICATIONS.find((f) => f.model === model && f.field === field);
  return entry?.classification ?? 'INTERNAL';
}

/** Atrod visus laukus ar konkrētu klasifikāciju */
export function getFieldsByClassification(
  classification: DataClassification,
): FieldClassification[] {
  return FIELD_CLASSIFICATIONS.filter((f) => f.classification === classification);
}

/** Atrod visus konkrēta modeļa laukus */
export function getModelFields(model: string): FieldClassification[] {
  return FIELD_CLASSIFICATIONS.filter((f) => f.model === model);
}

/** Vai pirmais līmenis ir vismaz tikpat strikts kā otrais */
export function isAtLeast(
  level: DataClassification,
  required: DataClassification,
): boolean {
  return CLASSIFICATION_LEVEL[level] >= CLASSIFICATION_LEVEL[required];
}
