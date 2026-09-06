import { randomBytes } from 'node:crypto';

/** Generate a request ID. */
export function createRequestId(): string {
  return `req_${randomBytes(8).toString('hex')}`;
}
