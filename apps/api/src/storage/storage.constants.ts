/** MinIO bucket nosaukumi — konfigurē caur .env vai noklusējuma vērtības */
export const BUCKETS = {
  /** Pieteikumu dokumenti (persondati — šifrēti at-rest) */
  DOCUMENTS: process.env.S3_BUCKET_DOCUMENTS || 'documents',
  /** Lietotāju fotogrāfijas */
  PHOTOS: process.env.S3_BUCKET_PHOTOS || 'photos',
  /** Izsniegtu sertifikātu PDF kopijas */
  CERTIFICATES: process.env.S3_BUCKET_CERTIFICATES || 'certificates',
  /** Eksporta faili (audita žurnāls, atskaites) */
  EXPORTS: process.env.S3_BUCKET_EXPORTS || 'exports',
  /** Pagaidu augšupielādes — tīra pēc 24h */
  TEMP: process.env.S3_BUCKET_TEMP || 'temp',
} as const;

export type BucketName = (typeof BUCKETS)[keyof typeof BUCKETS];

/** Atļautie failu formāti augšupielādei */
export const ALLOWED_MIME_TYPES = new Set([
  // Dokumenti
  'application/pdf',
  // Attēli
  'image/jpeg',
  'image/png',
  'image/webp',
  // Skenēti dokumenti
  'image/tiff',
]);

/** Atļautie paplašinājumi (papildu pārbaude — neuzticēties tikai MIME) */
export const ALLOWED_EXTENSIONS = new Set([
  '.pdf',
  '.jpg',
  '.jpeg',
  '.png',
  '.webp',
  '.tiff',
  '.tif',
]);

/** Noklusējuma maksimālais faila izmērs: 20 MB */
export const DEFAULT_MAX_FILE_SIZE = 20 * 1024 * 1024;

/** Presigned URL derīguma termiņi */
export const PRESIGNED_DOWNLOAD_EXPIRES = 15 * 60; // 15 min
export const PRESIGNED_UPLOAD_EXPIRES = 60 * 60;    // 60 min
