import { Prisma } from '@prisma/client';
import { getCurrentUserId } from '../common/request-context';

// Modeļi, kuriem ir createdBy/updatedBy lauki
const AUDITED_MODELS = ['User', 'UserNameHistory'] as const;

/**
 * Prisma extension — automātiski aizpilda createdBy/updatedBy no pieprasījuma konteksta.
 * Izmanto AsyncLocalStorage (request-context.ts) lai iegūtu userId.
 */
export const auditFieldsExtension = Prisma.defineExtension({
  query: {
    $allModels: {
      async create({ model, args, query }) {
        if (AUDITED_MODELS.includes(model as any)) {
          const userId = getCurrentUserId();
          if (userId && args.data && typeof args.data === 'object') {
            const data = args.data as Record<string, unknown>;
            if (data.createdBy === undefined) data.createdBy = userId;
            if ('updatedBy' in data && data.updatedBy === undefined) data.updatedBy = userId;
          }
        }
        return query(args);
      },

      async update({ model, args, query }) {
        if (AUDITED_MODELS.includes(model as any)) {
          const userId = getCurrentUserId();
          if (userId && args.data && typeof args.data === 'object') {
            const data = args.data as Record<string, unknown>;
            if (data.updatedBy === undefined) data.updatedBy = userId;
          }
        }
        return query(args);
      },

      async upsert({ model, args, query }) {
        if (AUDITED_MODELS.includes(model as any)) {
          const userId = getCurrentUserId();
          if (userId) {
            if (args.create && typeof args.create === 'object') {
              const create = args.create as Record<string, unknown>;
              if (create.createdBy === undefined) create.createdBy = userId;
            }
            if (args.update && typeof args.update === 'object') {
              const update = args.update as Record<string, unknown>;
              if (update.updatedBy === undefined) update.updatedBy = userId;
            }
          }
        }
        return query(args);
      },
    },
  },
});
