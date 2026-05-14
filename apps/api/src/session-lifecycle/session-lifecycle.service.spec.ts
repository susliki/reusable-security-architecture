import { SessionLifecycleService } from './session-lifecycle.service';

/*
Mock palīgi
*/

function makePrisma() {
  return {
    user: { update: jest.fn().mockResolvedValue({}) },
    session: { deleteMany: jest.fn().mockResolvedValue({ count: 0 }) },
  } as any;
}

function makeAudit() {
  return { write: jest.fn().mockResolvedValue({}) } as any;
}

function makePipeline() {
  const cmds: { op: string; args: any[] }[] = [];
  const pipe: any = {
    del: (...args: any[]) => { cmds.push({ op: 'del', args }); return pipe; },
    get: (...args: any[]) => { cmds.push({ op: 'get', args }); return pipe; },
    exists: (...args: any[]) => { cmds.push({ op: 'exists', args }); return pipe; },
    srem: (...args: any[]) => { cmds.push({ op: 'srem', args }); return pipe; },
    exec: jest.fn().mockResolvedValue(cmds.map(() => [null, null])),
    _cmds: cmds,
  };
  return pipe;
}

function makeRedisClient(overrides: Record<string, jest.Mock> = {}) {
  const pipes: any[] = [];
  const client: any = {
    get: jest.fn().mockResolvedValue(null),
    set: jest.fn().mockResolvedValue('OK'),
    del: jest.fn().mockResolvedValue(1),
    sadd: jest.fn().mockResolvedValue(1),
    srem: jest.fn().mockResolvedValue(1),
    smembers: jest.fn().mockResolvedValue([]),
    exists: jest.fn().mockResolvedValue(1),
    expire: jest.fn().mockResolvedValue(1),
    ttl: jest.fn().mockResolvedValue(3600),
    scan: jest.fn().mockResolvedValue(['0', []]),
    pipeline: jest.fn(() => {
      const p = makePipeline();
      pipes.push(p);
      return p;
    }),
    _pipes: pipes,
    ...overrides,
  };
  return client;
}

function makeRedis(client?: any) {
  return { getClient: jest.fn(() => client ?? makeRedisClient()) } as any;
}

function makeAuditCtx(reason = 'admin_force_logout' as any) {
  return {
    actorUserId: 'admin-1',
    actorRole: 'ADMIN',
    clientIp: '127.0.0.1',
    userAgent: 'test-agent',
    reason,
  };
}

function makeSession(id = 'sess-1') {
  return {
    id,
    userId: 'u1',
    destroy: jest.fn((cb: (err?: unknown) => void) => cb()),
  };
}

/*
Testi
*/

describe('SessionLifecycleService', () => {
  let service: SessionLifecycleService;
  let prisma: ReturnType<typeof makePrisma>;
  let audit: ReturnType<typeof makeAudit>;
  let client: any;
  let redis: any;

  beforeEach(() => {
    jest.clearAllMocks();
    prisma = makePrisma();
    audit = makeAudit();
    client = makeRedisClient();
    redis = makeRedis(client);
    service = new SessionLifecycleService(prisma, redis, audit);
    process.env.SESSION_ABSOLUTE_TTL = '28800';
  });

  /*
  findTrackedSessionKeys
  */

  describe('findTrackedSessionKeys', () => {
    it('atgriež indeksētās sesijas un noņem novecojušas', async () => {
      client.exists.mockResolvedValue(1); // migrated marķieris eksistē
      client.smembers.mockResolvedValue(['sess:a', 'sess:b', 'sess:c']);

      // Pipeline EXISTS: a=eksistē, b=neeksistē, c=eksistē
      client.pipeline.mockReturnValue({
        exists: jest.fn().mockReturnThis(),
        exec: jest.fn().mockResolvedValue([
          [null, 1], // sess:a eksistē
          [null, 0], // sess:b neeksistē
          [null, 1], // sess:c eksistē
        ]),
      });

      const result = await service.findTrackedSessionKeys('u1');

      expect(result).toEqual(['sess:a', 'sess:c']);
      // Noņem novecojušo sess:b no indeksa
      expect(client.srem).toHaveBeenCalledWith('user-sessions:u1', 'sess:b');
    });

    it('izpilda SCAN migrācijas fallback ja marķieris neeksistē', async () => {
      client.exists.mockResolvedValue(0); // marķieris neeksistē
      // SCAN atrod vienu sesiju kas pieder u1
      client.scan.mockResolvedValue(['0', ['sess:x', 'sess:y']]);
      client.get
        .mockResolvedValueOnce(JSON.stringify({ userId: 'u1' })) // sess:x — pieder u1
        .mockResolvedValueOnce(JSON.stringify({ userId: 'u2' })); // sess:y — cits lietotājs
      client.smembers.mockResolvedValue(['sess:x']);

      // Pipeline EXISTS: sess:x eksistē
      client.pipeline.mockReturnValue({
        exists: jest.fn().mockReturnThis(),
        exec: jest.fn().mockResolvedValue([[null, 1]]),
      });

      const result = await service.findTrackedSessionKeys('u1');

      expect(result).toEqual(['sess:x']);
      // Pievieno atrasto sesiju indeksam
      expect(client.sadd).toHaveBeenCalledWith('user-sessions:u1', 'sess:x');
      // Uzstāda migrācijas marķieri
      expect(client.set).toHaveBeenCalledWith(
        'user-sessions:u1:migrated', '1', 'EX', expect.any(Number),
      );
    });

    it('izlaiž migrāciju ja marķieris eksistē', async () => {
      client.exists.mockResolvedValue(1); // marķieris eksistē
      client.smembers.mockResolvedValue([]);

      const result = await service.findTrackedSessionKeys('u1');

      expect(result).toEqual([]);
      expect(client.scan).not.toHaveBeenCalled();
    });
  });

  /*
  establishAuthenticatedSession
  */

  describe('establishAuthenticatedSession', () => {
    it('reģenerē sesiju, saglabā laukus, pievieno indeksam', async () => {
      const req: any = {
        session: {
          csrfSecret: 'csrf-token',
          regenerate: jest.fn((cb: (err?: Error | null) => void) => {
            // Pēc regenerācijas req.session ir jauns objekts
            req.session = {
              ...req.session,
              id: 'new-sess-id',
              save: jest.fn((cb2: (err?: Error | null) => void) => cb2()),
            };
            cb(null);
          }),
          id: 'old-sess-id',
          save: jest.fn((cb: (err?: Error | null) => void) => cb()),
        },
      };

      await service.establishAuthenticatedSession({
        req,
        userId: 'u1',
        role: 'ADMIN',
        firstName: 'Jānis',
        lastName: 'Bērziņš',
        clientIp: '10.0.0.1',
        userAgent: 'Chrome/120',
      });

      // Sesijas lauki
      expect(req.session.userId).toBe('u1');
      expect(req.session.userRole).toBe('ADMIN');
      expect(req.session.isAdmin).toBe(true);
      expect(req.session.firstName).toBe('Jānis');
      expect(req.session.lastName).toBe('Bērziņš');
      expect(req.session.csrfSecret).toBe('csrf-token');

      // DB — lastLoginAt
      expect(prisma.user.update).toHaveBeenCalledWith({
        where: { id: 'u1' },
        data: { lastLoginAt: expect.any(Date) },
      });

      // Redis Set indekss
      expect(client.sadd).toHaveBeenCalledWith(
        'user-sessions:u1', 'sess:new-sess-id',
      );
    });
  });

  /*
  enforceSessionLimit
  */

  describe('enforceSessionLimit', () => {
    it('dzēš vecākās sesijas ja pārsniegts limits', async () => {
      client.exists.mockResolvedValue(1); // migrated
      client.smembers.mockResolvedValue(['sess:a', 'sess:b', 'sess:c']);

      // EXISTS pipeline — visas eksistē
      const existsPipe = {
        exists: jest.fn().mockReturnThis(),
        exec: jest.fn().mockResolvedValue([[null, 1], [null, 1], [null, 1]]),
      };
      // GET pipeline — ar lastActive laikiem
      const getPipe = {
        get: jest.fn().mockReturnThis(),
        exec: jest.fn().mockResolvedValue([
          [null, JSON.stringify({ lastActive: '2026-01-01T00:00:00Z' })], // vecākā
          [null, JSON.stringify({ lastActive: '2026-01-03T00:00:00Z' })], // jaunākā
          [null, JSON.stringify({ lastActive: '2026-01-02T00:00:00Z' })], // vidējā
        ]),
      };
      // DEL pipeline
      const delPipe = {
        del: jest.fn().mockReturnThis(),
        srem: jest.fn().mockReturnThis(),
        exec: jest.fn().mockResolvedValue([]),
      };

      client.pipeline
        .mockReturnValueOnce(existsPipe) // findTrackedSessionKeys EXISTS
        .mockReturnValueOnce(getPipe)    // enforceSessionLimit GET
        .mockReturnValueOnce(delPipe);   // enforceSessionLimit DEL

      await service.enforceSessionLimit('u1', 2);

      // Jādzēš 1 sesija (3 - 2 = 1), vecākā sess:a
      expect(delPipe.del).toHaveBeenCalledWith('sess:a');
      expect(delPipe.srem).toHaveBeenCalledWith('user-sessions:u1', 'sess:a');
      expect(delPipe.exec).toHaveBeenCalled();
    });

    it('neko nedara ja under limit', async () => {
      client.exists.mockResolvedValue(1);
      client.smembers.mockResolvedValue(['sess:a']);
      client.pipeline.mockReturnValue({
        exists: jest.fn().mockReturnThis(),
        exec: jest.fn().mockResolvedValue([[null, 1]]),
      });

      await service.enforceSessionLimit('u1', 5);

      // Nav GET pipeline izsaukuma — nevajag pārbaudīt vecumu
      expect(client.pipeline).toHaveBeenCalledTimes(1); // tikai EXISTS
    });
  });

  /*
  revokeAllUserSessions
  */

  describe('revokeAllUserSessions', () => {
    it('dzēš Redis sesijas + DB ierakstus + indeksu + marķieri', async () => {
      client.exists.mockResolvedValue(1);
      client.smembers.mockResolvedValue(['sess:a', 'sess:b']);

      // EXISTS pipeline
      client.pipeline.mockReturnValueOnce({
        exists: jest.fn().mockReturnThis(),
        exec: jest.fn().mockResolvedValue([[null, 1], [null, 1]]),
      });
      // DEL pipeline
      const delPipe = {
        del: jest.fn().mockReturnThis(),
        exec: jest.fn().mockResolvedValue([]),
      };
      client.pipeline.mockReturnValueOnce(delPipe);

      prisma.session.deleteMany.mockResolvedValue({ count: 1 });

      const result = await service.revokeAllUserSessions({
        userId: 'u1',
        audit: makeAuditCtx(),
      });

      expect(result).toEqual({ revokedRedis: 2, deletedDb: 1 });

      // Redis sesijas dzēstas ar pipeline
      expect(delPipe.del).toHaveBeenCalledWith('sess:a');
      expect(delPipe.del).toHaveBeenCalledWith('sess:b');

      // Indekss un marķieris dzēsti
      expect(client.del).toHaveBeenCalledWith('user-sessions:u1', 'user-sessions:u1:migrated');

      // DB sesijas dzēstas
      expect(prisma.session.deleteMany).toHaveBeenCalledWith({ where: { userId: 'u1' } });

      // Audita ieraksts
      expect(audit.write).toHaveBeenCalledWith(
        expect.objectContaining({
          action: 'session.revoke_all',
          subjectId: 'u1',
          dataJson: expect.objectContaining({
            reason: 'admin_force_logout',
            revokedRedis: 2,
            deletedDb: 1,
          }),
        }),
      );
    });

    it('apstrādā tukšu sesiju sarakstu', async () => {
      client.exists.mockResolvedValue(1);
      client.smembers.mockResolvedValue([]);
      prisma.session.deleteMany.mockResolvedValue({ count: 0 });

      const result = await service.revokeAllUserSessions({
        userId: 'u1',
        audit: makeAuditCtx(),
      });

      expect(result).toEqual({ revokedRedis: 0, deletedDb: 0 });
    });
  });

  /*
  revokeOtherUserSessions
  */

  describe('revokeOtherUserSessions', () => {
    it('saglabā pašreizējo sesiju, dzēš pārējās', async () => {
      client.exists.mockResolvedValue(1);
      client.smembers.mockResolvedValue(['sess:current', 'sess:other1', 'sess:other2']);

      // EXISTS pipeline
      client.pipeline.mockReturnValueOnce({
        exists: jest.fn().mockReturnThis(),
        exec: jest.fn().mockResolvedValue([[null, 1], [null, 1], [null, 1]]),
      });
      // DEL + SREM pipeline
      const delPipe = {
        del: jest.fn().mockReturnThis(),
        srem: jest.fn().mockReturnThis(),
        exec: jest.fn().mockResolvedValue([]),
      };
      client.pipeline.mockReturnValueOnce(delPipe);

      const result = await service.revokeOtherUserSessions({
        userId: 'u1',
        currentSessionId: 'current',
        audit: makeAuditCtx('passkey_revoked'),
      });

      expect(result).toEqual({ revokedRedis: 2 });

      // Pašreizējā sesija NAV dzēsta
      expect(delPipe.del).not.toHaveBeenCalledWith('sess:current');
      // Pārējās dzēstas
      expect(delPipe.del).toHaveBeenCalledWith('sess:other1');
      expect(delPipe.del).toHaveBeenCalledWith('sess:other2');

      // Audits ar pareizu reason
      expect(audit.write).toHaveBeenCalledWith(
        expect.objectContaining({
          action: 'session.revoke_others',
          dataJson: expect.objectContaining({
            reason: 'passkey_revoked',
            revokedRedis: 2,
            preservedSessionId: 'current',
          }),
        }),
      );
    });
  });

  /*
  logoutSession
  */

  describe('logoutSession', () => {
    it('noņem no indeksa un iznīcina express sesiju', async () => {
      const session = makeSession('sess-1');

      await service.logoutSession({
        session,
        userId: 'u1',
        sessionId: 'sess-1',
        audit: makeAuditCtx('logout'),
      });

      // SREM no indeksa
      expect(client.srem).toHaveBeenCalledWith('user-sessions:u1', 'sess:sess-1');

      // Express session destroy izsaukts
      expect(session.destroy).toHaveBeenCalled();

      // Audita ieraksts
      expect(audit.write).toHaveBeenCalledWith(
        expect.objectContaining({
          action: 'session.logout',
          subjectId: 'u1',
        }),
      );
    });
  });

  /*
  revokeSessionById
  */

  describe('revokeSessionById', () => {
    it('dzēš sesiju un noņem no indeksa', async () => {
      client.get.mockResolvedValue(JSON.stringify({ userId: 'u1' }));

      const result = await service.revokeSessionById({
        sessionId: 'target-sess',
        audit: makeAuditCtx('admin_session_revoke'),
      });

      expect(result).toEqual({ found: true });
      expect(client.del).toHaveBeenCalledWith('sess:target-sess');
      expect(client.srem).toHaveBeenCalledWith('user-sessions:u1', 'sess:target-sess');
      expect(audit.write).toHaveBeenCalledWith(
        expect.objectContaining({
          action: 'admin.session.revoke',
          entityId: 'target-sess',
        }),
      );
    });

    it('atgriež found=false ja sesija neeksistē', async () => {
      client.get.mockResolvedValue(null);

      const result = await service.revokeSessionById({
        sessionId: 'missing-sess',
        audit: makeAuditCtx('admin_session_revoke'),
      });

      expect(result).toEqual({ found: false });
      expect(client.del).not.toHaveBeenCalledWith('sess:missing-sess');
    });
  });

  /*
  listAllSessions
  */

  describe('listAllSessions', () => {
    it('atgriež sesiju sarakstu ar kopsavilkumu', async () => {
      client.scan.mockResolvedValue(['0', ['sess:a']]);
      client.get.mockResolvedValue(JSON.stringify({
        userId: 'u1',
        firstName: 'Jānis',
        lastName: 'Bērziņš',
        userRole: 'ADMIN',
        isAdmin: true,
        clientIp: '10.0.0.1',
        userAgent: 'Chrome/120',
        createdAt: '2026-04-12T10:00:00Z',
        cookie: {
          expires: new Date(Date.now() + 3600_000).toISOString(),
          originalMaxAge: 3600_000,
        },
      }));
      client.ttl.mockResolvedValue(3500);

      const result = await service.listAllSessions();

      expect(result.sessions).toHaveLength(1);
      expect(result.sessions[0]).toEqual(expect.objectContaining({
        sessionId: 'a',
        userId: 'u1',
        userRole: 'ADMIN',
        browser: expect.any(String),
      }));
      expect(result.summary.total).toBe(1);
      expect(result.summary.byRole).toEqual({ ADMIN: 1 });
    });
  });
});
