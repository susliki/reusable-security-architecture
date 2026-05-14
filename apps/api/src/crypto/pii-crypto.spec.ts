import {
  encryptField,
  decryptField,
  blindIndex,
  isEncryptedValue,
  _resetKeyCache,
} from './pii-crypto';

// Testa atslēgas — 32 baiti hex
const TEST_ENC_KEY = 'a'.repeat(64);
const TEST_IDX_KEY = 'b'.repeat(64);

beforeEach(() => {
  _resetKeyCache();
  process.env.PII_ENCRYPTION_KEY = TEST_ENC_KEY;
  process.env.PII_BLIND_INDEX_KEY = TEST_IDX_KEY;
});

afterEach(() => {
  _resetKeyCache();
  delete process.env.PII_ENCRYPTION_KEY;
  delete process.env.PII_BLIND_INDEX_KEY;
});

describe('encryptField / decryptField', () => {
  it('šifrē un atšifrē tekstu', () => {
    const plain = 'jurnieks@example.com';
    const cipher = encryptField(plain);
    expect(cipher).not.toBe(plain);
    expect(decryptField(cipher)).toBe(plain);
  });

  it('katrs šifrējums ir unikāls (jauns IV)', () => {
    const plain = 'test@test.lv';
    const a = encryptField(plain);
    const b = encryptField(plain);
    expect(a).not.toBe(b);
    // Abi atšifrējas uz to pašu
    expect(decryptField(a)).toBe(plain);
    expect(decryptField(b)).toBe(plain);
  });

  it('apstrādā tukšu virkni', () => {
    const cipher = encryptField('');
    expect(decryptField(cipher)).toBe('');
  });

  it('apstrādā UTF-8 (latviešu burtus)', () => {
    const plain = 'Jānis Bērziņš';
    expect(decryptField(encryptField(plain))).toBe(plain);
  });

  it('izmet kļūdu ja atslēga nav iestatīta', () => {
    _resetKeyCache();
    delete process.env.PII_ENCRYPTION_KEY;
    expect(() => encryptField('test')).toThrow('PII_ENCRYPTION_KEY');
  });

  it('izmet kļūdu ja atslēga ir nepareiza garuma', () => {
    _resetKeyCache();
    process.env.PII_ENCRYPTION_KEY = 'tooshort';
    expect(() => encryptField('test')).toThrow('32-baitu');
  });
});

describe('blindIndex', () => {
  it('rada deterministisku vērtību', () => {
    const a = blindIndex('Test@Example.com');
    const b = blindIndex('test@example.com');
    expect(a).toBe(b);
  });

  it('atšķiras dažādām vērtībām', () => {
    const a = blindIndex('alice@example.com');
    const b = blindIndex('bob@example.com');
    expect(a).not.toBe(b);
  });

  it('apstrādā atstarpes', () => {
    const a = blindIndex('  test@test.lv  ');
    const b = blindIndex('test@test.lv');
    expect(a).toBe(b);
  });
});

describe('isEncryptedValue', () => {
  it('atpazīst šifrētu vērtību', () => {
    const cipher = encryptField('test');
    expect(isEncryptedValue(cipher)).toBe(true);
  });

  it('atpazīst plaintext e-pastu', () => {
    expect(isEncryptedValue('user@example.com')).toBe(false);
  });
});
