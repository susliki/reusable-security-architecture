-- CreateEnum
CREATE TYPE "Role" AS ENUM ('USER', 'OPERATOR', 'ADMIN');

-- CreateEnum
CREATE TYPE "UserStatus" AS ENUM ('UNVERIFIED', 'PENDING_REVIEW', 'VERIFIED', 'REJECTED', 'BLOCKED', 'DELETED');

-- CreateEnum
CREATE TYPE "IdentityProvider" AS ENUM ('PASSKEY', 'TOTP', 'ENTRA', 'EXTERNAL_EID');

-- CreateEnum
CREATE TYPE "RectificationStatus" AS ENUM ('PENDING', 'APPROVED', 'REJECTED');

-- CreateTable
CREATE TABLE "User" (
    "id" TEXT NOT NULL,
    "email" TEXT,
    "emailHmac" TEXT,
    "firstName" TEXT,
    "lastName" TEXT,
    "phone" TEXT,
    "citizenship" TEXT,
    "dateOfBirth" TEXT,
    "sex" CHAR(1),
    "birthPlace" TEXT,
    "personalCodeEnc" TEXT,
    "address" TEXT,
    "role" "Role" NOT NULL DEFAULT 'USER',
    "status" "UserStatus" NOT NULL DEFAULT 'UNVERIFIED',
    "emailNotify" BOOLEAN NOT NULL DEFAULT true,
    "smsNotify" BOOLEAN NOT NULL DEFAULT false,
    "identityVerifiedAt" TIMESTAMP(3),
    "identityVerifiedBy" TEXT,
    "verificationMethod" TEXT,
    "idCodeHmac" TEXT,
    "profileSubmittedAt" TIMESTAMP(3),
    "rejectionReason" TEXT,
    "entraRole" TEXT,
    "consentedAt" TIMESTAMP(3),
    "consentedPolicyVersion" VARCHAR(20),
    "deletedAt" TIMESTAMP(3),
    "lastLoginAt" TIMESTAMP(3),
    "createdBy" TEXT,
    "updatedBy" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "User_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Identity" (
    "id" TEXT NOT NULL,
    "provider" "IdentityProvider" NOT NULL,
    "providerId" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "secret" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Identity_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "PasskeyCredential" (
    "id" TEXT NOT NULL,
    "identityId" TEXT NOT NULL,
    "credentialId" TEXT NOT NULL,
    "publicKey" TEXT NOT NULL,
    "counter" BIGINT NOT NULL DEFAULT 0,
    "transports" TEXT[],
    "name" TEXT,
    "uvInitialized" BOOLEAN NOT NULL DEFAULT false,
    "lastUsedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "PasskeyCredential_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Session" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Session_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "VerificationDocument" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "type" TEXT NOT NULL,
    "storageKey" TEXT NOT NULL,
    "mimeType" TEXT NOT NULL,
    "fileSize" INTEGER NOT NULL,
    "scanStatus" TEXT NOT NULL DEFAULT 'PENDING',
    "uploadedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "VerificationDocument_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "UserConsent" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "type" VARCHAR(50) NOT NULL,
    "version" VARCHAR(20) NOT NULL,
    "accepted" BOOLEAN NOT NULL DEFAULT true,
    "givenAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "revokedAt" TIMESTAMP(3),
    "ipAddress" VARCHAR(45),
    "userAgent" VARCHAR(256),

    CONSTRAINT "UserConsent_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "RectificationRequest" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "field" VARCHAR(64) NOT NULL,
    "currentValue" VARCHAR(500) NOT NULL,
    "requestedValue" VARCHAR(500) NOT NULL,
    "reason" VARCHAR(500),
    "status" "RectificationStatus" NOT NULL DEFAULT 'PENDING',
    "reviewedBy" TEXT,
    "reviewNote" VARCHAR(500),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "RectificationRequest_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Notification" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "type" VARCHAR(32) NOT NULL,
    "title" VARCHAR(200) NOT NULL,
    "description" VARCHAR(500) NOT NULL,
    "read" BOOLEAN NOT NULL DEFAULT false,
    "actionUrl" VARCHAR(300),
    "actionLabel" VARCHAR(100),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Notification_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "UserNameHistory" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "previousFirst" TEXT,
    "previousLast" TEXT,
    "newFirst" TEXT,
    "newLast" TEXT,
    "changedAt" TIMESTAMP(3) NOT NULL,
    "documentRef" VARCHAR(200),
    "reason" VARCHAR(200),
    "createdBy" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "UserNameHistory_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AuditLog" (
    "id" UUID NOT NULL,
    "ts" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "seq" BIGSERIAL NOT NULL,
    "rid" VARCHAR(64),
    "subjectId" VARCHAR(128),
    "subjectRole" VARCHAR(64),
    "action" VARCHAR(64) NOT NULL,
    "entityType" VARCHAR(64),
    "entityId" VARCHAR(64),
    "result" VARCHAR(16) NOT NULL,
    "clientIp" VARCHAR(45),
    "userAgent" VARCHAR(256),
    "prevHash" VARCHAR(88),
    "hash" VARCHAR(88) NOT NULL,
    "dataJson" JSONB,

    CONSTRAINT "AuditLog_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "User_email_key" ON "User"("email");

-- CreateIndex
CREATE UNIQUE INDEX "User_emailHmac_key" ON "User"("emailHmac");

-- CreateIndex
CREATE UNIQUE INDEX "User_idCodeHmac_key" ON "User"("idCodeHmac");

-- CreateIndex
CREATE UNIQUE INDEX "Identity_provider_providerId_key" ON "Identity"("provider", "providerId");

-- CreateIndex
CREATE UNIQUE INDEX "PasskeyCredential_identityId_key" ON "PasskeyCredential"("identityId");

-- CreateIndex
CREATE UNIQUE INDEX "PasskeyCredential_credentialId_key" ON "PasskeyCredential"("credentialId");

-- CreateIndex
CREATE INDEX "UserConsent_userId_type_givenAt_idx" ON "UserConsent"("userId", "type", "givenAt" DESC);

-- CreateIndex
CREATE INDEX "UserConsent_version_idx" ON "UserConsent"("version");

-- CreateIndex
CREATE INDEX "RectificationRequest_userId_createdAt_idx" ON "RectificationRequest"("userId", "createdAt" DESC);

-- CreateIndex
CREATE INDEX "RectificationRequest_status_createdAt_idx" ON "RectificationRequest"("status", "createdAt" DESC);

-- CreateIndex
CREATE INDEX "Notification_userId_read_createdAt_idx" ON "Notification"("userId", "read", "createdAt" DESC);

-- CreateIndex
CREATE INDEX "UserNameHistory_userId_changedAt_idx" ON "UserNameHistory"("userId", "changedAt" DESC);

-- CreateIndex
CREATE UNIQUE INDEX "AuditLog_seq_key" ON "AuditLog"("seq");

-- CreateIndex
CREATE INDEX "AuditLog_ts_idx" ON "AuditLog"("ts" DESC);

-- CreateIndex
CREATE INDEX "AuditLog_action_ts_idx" ON "AuditLog"("action", "ts" DESC);

-- CreateIndex
CREATE INDEX "AuditLog_entityType_entityId_ts_idx" ON "AuditLog"("entityType", "entityId", "ts" DESC);

-- CreateIndex
CREATE INDEX "AuditLog_subjectId_ts_idx" ON "AuditLog"("subjectId", "ts" DESC);

-- AddForeignKey
ALTER TABLE "Identity" ADD CONSTRAINT "Identity_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "PasskeyCredential" ADD CONSTRAINT "PasskeyCredential_identityId_fkey" FOREIGN KEY ("identityId") REFERENCES "Identity"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Session" ADD CONSTRAINT "Session_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "VerificationDocument" ADD CONSTRAINT "VerificationDocument_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "UserConsent" ADD CONSTRAINT "UserConsent_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "RectificationRequest" ADD CONSTRAINT "RectificationRequest_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "RectificationRequest" ADD CONSTRAINT "RectificationRequest_reviewedBy_fkey" FOREIGN KEY ("reviewedBy") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Notification" ADD CONSTRAINT "Notification_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "UserNameHistory" ADD CONSTRAINT "UserNameHistory_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
