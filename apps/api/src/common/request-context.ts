import { AsyncLocalStorage } from 'async_hooks';

// Pieprasījuma konteksts — pārnes userId caur async operācijām
// Prisma extension izmanto, lai automātiski aizpildītu createdBy/updatedBy
interface RequestContext {
  userId?: string;
}

export const requestContextStore = new AsyncLocalStorage<RequestContext>();

/** Atgriež pašreizējo userId no pieprasījuma konteksta */
export function getCurrentUserId(): string | undefined {
  return requestContextStore.getStore()?.userId;
}
