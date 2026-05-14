/** BullMQ rindu nosaukumi — centralizēti, lai izvairītos no literāļu kļūdām */
export const QUEUES = {
  EMAIL: 'email',
  SMS: 'sms',
  DATA_RETENTION: 'data-retention',
} as const;

export type QueueName = (typeof QUEUES)[keyof typeof QUEUES];

/** Noklusējuma darbu opcijas */
export const DEFAULT_JOB_OPTS = {
  attempts: 3,
  backoff: {
    type: 'exponential' as const,
    delay: 3_000, // 3s → 6s → 12s
  },
  removeOnComplete: { age: 7 * 24 * 3600 }, // 7 dienas
  removeOnFail: { age: 30 * 24 * 3600 },    // 30 dienas
};
