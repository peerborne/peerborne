import type { ConnectionErrorType } from '@peerborne/core';

export type SharingStage =
  | 'relay-connection'
  | 'relay-reservation'
  | 'invitation';

const messages: Record<SharingStage, string> = {
  'relay-connection':
    'Could not connect to the relay. Please try again shortly.',
  'relay-reservation':
    'The relay did not become ready in time. Please try again shortly.',
  invitation: 'A share link could not be created. Please try again.',
};

export class NoteSharingError extends Error {
  readonly diagnostic: Readonly<{
    stage: SharingStage;
    errorType: ConnectionErrorType;
    attempts: number;
    elapsedMs: number;
  }>;

  constructor(
    stage: SharingStage,
    cause: unknown,
    errorType: ConnectionErrorType,
    attempts: number,
    elapsedMs: number,
  ) {
    super(messages[stage], { cause });
    this.name = 'NoteSharingError';
    this.diagnostic = Object.freeze({ stage, errorType, attempts, elapsedMs });
  }
}
