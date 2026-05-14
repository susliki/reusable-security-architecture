/*
Failu glabātuves serviss — iesaiņo MinIO (S3 saderīgu) klientu.
Buckets: avatars, certificates, applications, audit-archive — katram sava dzīves cikla politika.
Pirms saglabāšanas faili obligāti iziet ClamAV skenēšanu un MIME/paplašinājuma validāciju.
*/

import {
  BadRequestException,
  Injectable,
  Logger,
  OnModuleInit,
  UnprocessableEntityException,
} from '@nestjs/common';
import {
  S3Client,
  PutObjectCommand,
  GetObjectCommand,
  DeleteObjectCommand,
  ListObjectsV2Command,
  HeadBucketCommand,
} from '@aws-sdk/client-s3';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';
import { extname } from 'path';
import {
  ALLOWED_EXTENSIONS,
  ALLOWED_MIME_TYPES,
  DEFAULT_MAX_FILE_SIZE,
  PRESIGNED_DOWNLOAD_EXPIRES,
  PRESIGNED_UPLOAD_EXPIRES,
  type BucketName,
} from './storage.constants';
import { ClamavService } from './clamav.service';
import { AuditService } from '../audit/audit.service';

type FileMetadata = Record<string, string>;

type UploadResult = {
  bucket: string;
  key: string;
  size: number;
};

type FileInfo = {
  key: string;
  size: number;
  lastModified: Date | undefined;
};

@Injectable()
export class StorageService implements OnModuleInit {
  private readonly logger = new Logger(StorageService.name);
  private client!: S3Client;

  constructor(
    private readonly clamav: ClamavService,
    private readonly audit: AuditService,
  ) {}

  onModuleInit() {
    const endpoint = process.env.S3_ENDPOINT || 'http://localhost:9000';
    const accessKey = process.env.S3_ACCESS_KEY || 'minioadmin';
    const secretKey = process.env.S3_SECRET_KEY || 'minioadmin';
    const region = process.env.S3_REGION || 'us-east-1';

    this.client = new S3Client({
      endpoint,
      region,
      credentials: {
        accessKeyId: accessKey,
        secretAccessKey: secretKey,
      },
      forcePathStyle: true, // MinIO prasība — path-style, ne virtual-hosted
    });

    this.logger.log(`MinIO savienots: ${endpoint}`);
  }

  /**
   * Augšupielādēt failu ar validāciju.
   * Pārbauda izmēru un formātu PIRMS sūtīšanas uz MinIO.
   */
  async uploadFile(
    bucket: BucketName,
    key: string,
    buffer: Buffer,
    metadata?: FileMetadata & { contentType?: string },
    opts?: { maxSize?: number },
  ): Promise<UploadResult> {
    const maxSize = opts?.maxSize ?? DEFAULT_MAX_FILE_SIZE;

    // Izmēra pārbaude
    if (buffer.length > maxSize) {
      throw new BadRequestException({
        code: 'file_too_large',
        message: `Fails pārsniedz maksimālo izmēru (${Math.round(maxSize / 1024 / 1024)} MB)`,
      });
    }

    // Formāta pārbaude — paplašinājums
    const ext = extname(key).toLowerCase();
    if (!ALLOWED_EXTENSIONS.has(ext)) {
      throw new BadRequestException({
        code: 'file_type_not_allowed',
        message: `Faila formāts "${ext}" nav atļauts`,
      });
    }

    // Formāta pārbaude — MIME tips (ja norādīts)
    const contentType = metadata?.contentType;
    if (contentType && !ALLOWED_MIME_TYPES.has(contentType)) {
      throw new BadRequestException({
        code: 'mime_type_not_allowed',
        message: `MIME tips "${contentType}" nav atļauts`,
      });
    }

    // Vīrusu pārbaude — PIRMS augšupielādes uz MinIO
    // Ja ClamAV nav pieejams vai skenēšana neizdevās — noraidām failu (nekad nepieņemam bez skenēšanas)
    try {
      const scan = await this.clamav.scanBuffer(buffer);
      if (!scan.clean) {
        this.logger.warn(`Vīruss atrasts failā "${key}": ${scan.virus}`);
        // Audita ieraksts par vīrusa atrašanu
        await this.audit.write({
          action: 'file.virus_detected',
          entityType: 'file',
          entityId: key,
          result: 'Denied',
          dataJson: { bucket, virus: scan.virus, size: buffer.length },
        }).catch((err) => {
          this.logger.error(`Audita ieraksta kļūda: ${err.message}`);
        });
        throw new UnprocessableEntityException({
          code: 'virus_detected',
          message: `Failā atrasts vīruss: ${scan.virus}`,
        });
      }
    } catch (err) {
      // Ja kļūda jau ir UnprocessableEntityException — pārsviežam tālāk
      if (err instanceof UnprocessableEntityException) throw err;
      // ClamAV nav pieejams — noraidām augšupielādi (drošības politika)
      this.logger.error(`ClamAV skenēšanas kļūda: ${(err as Error).message}`);
      throw new UnprocessableEntityException({
        code: 'virus_scan_unavailable',
        message: 'Vīrusu pārbaude nav pieejama. Augšupielāde noraidīta.',
      });
    }

    // Atdalīt contentType no pārējiem metadata
    const { contentType: _, ...userMetadata } = metadata ?? {};

    await this.client.send(
      new PutObjectCommand({
        Bucket: bucket,
        Key: key,
        Body: buffer,
        ContentType: contentType ?? 'application/octet-stream',
        Metadata: userMetadata,
      }),
    );

    return { bucket, key, size: buffer.length };
  }

  /** Presigned lejupielādes URL — 15 min noklusējums */
  async getDownloadUrl(
    bucket: BucketName,
    key: string,
    expiresIn = PRESIGNED_DOWNLOAD_EXPIRES,
  ): Promise<string> {
    const command = new GetObjectCommand({ Bucket: bucket, Key: key });
    return getSignedUrl(this.client, command, { expiresIn });
  }

  /** Presigned augšupielādes URL — 60 min noklusējums */
  async getUploadUrl(
    bucket: BucketName,
    key: string,
    contentType: string,
    expiresIn = PRESIGNED_UPLOAD_EXPIRES,
  ): Promise<string> {
    const command = new PutObjectCommand({
      Bucket: bucket,
      Key: key,
      ContentType: contentType,
    });
    return getSignedUrl(this.client, command, { expiresIn });
  }

  /** Dzēst failu */
  async deleteFile(bucket: BucketName, key: string): Promise<void> {
    await this.client.send(
      new DeleteObjectCommand({ Bucket: bucket, Key: key }),
    );
  }

  /** Uzskaitīt failus pēc prefiksa */
  async listFiles(
    bucket: BucketName,
    prefix: string,
    maxKeys = 100,
  ): Promise<FileInfo[]> {
    const result = await this.client.send(
      new ListObjectsV2Command({
        Bucket: bucket,
        Prefix: prefix,
        MaxKeys: maxKeys,
      }),
    );

    return (result.Contents ?? []).map((obj) => ({
      key: obj.Key ?? '',
      size: obj.Size ?? 0,
      lastModified: obj.LastModified,
    }));
  }

  /** Veselības pārbaude — HeadBucket uz jebkuru bucket */
  async ping(bucket: BucketName): Promise<boolean> {
    try {
      await this.client.send(new HeadBucketCommand({ Bucket: bucket }));
      return true;
    } catch {
      return false;
    }
  }
}
