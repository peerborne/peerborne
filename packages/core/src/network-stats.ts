/**
 * Counter container for network statistics.
 *
 * Enable via `enableNetworkStats: true` in PeerborneConfig, then access
 * via `peerborne.networkStats`. Callers must invoke `record*()` methods
 * explicitly to update counters -- automatic event wiring is not yet
 * implemented and will be added in a follow-up.
 */
export class NetworkStats {
  private _messagesSent = 0;
  private _messagesReceived = 0;
  private _bytesSent = 0;
  private _bytesReceived = 0;
  private _documentsOpened = 0;
  private _documentsClosed = 0;
  private _peersConnected = 0;
  private _peersDisconnected = 0;

  private static _validateBytes(bytes: number): number {
    if (!Number.isFinite(bytes) || bytes < 0) return 0;
    return bytes;
  }

  /** Record an outgoing message. */
  recordSent(bytes: number): void {
    this._messagesSent++;
    this._bytesSent += NetworkStats._validateBytes(bytes);
  }

  /** Record an incoming message. */
  recordReceived(bytes: number): void {
    this._messagesReceived++;
    this._bytesReceived += NetworkStats._validateBytes(bytes);
  }

  /** Record a document open. */
  recordDocumentOpen(): void {
    this._documentsOpened++;
  }

  /** Record a document close. */
  recordDocumentClose(): void {
    this._documentsClosed++;
  }

  /** Record a peer connection. */
  recordPeerConnect(): void {
    this._peersConnected++;
  }

  /** Record a peer disconnection. */
  recordPeerDisconnect(): void {
    this._peersDisconnected++;
  }

  /** Get a snapshot of current statistics. */
  snapshot(): NetworkStatsSnapshot {
    return {
      messagesSent: this._messagesSent,
      messagesReceived: this._messagesReceived,
      bytesSent: this._bytesSent,
      bytesReceived: this._bytesReceived,
      documentsOpened: this._documentsOpened,
      documentsClosed: this._documentsClosed,
      peersConnected: this._peersConnected,
      peersDisconnected: this._peersDisconnected,
    };
  }

  /** Reset all counters to zero. */
  reset(): void {
    this._messagesSent = 0;
    this._messagesReceived = 0;
    this._bytesSent = 0;
    this._bytesReceived = 0;
    this._documentsOpened = 0;
    this._documentsClosed = 0;
    this._peersConnected = 0;
    this._peersDisconnected = 0;
  }
}

export interface NetworkStatsSnapshot {
  messagesSent: number;
  messagesReceived: number;
  bytesSent: number;
  bytesReceived: number;
  documentsOpened: number;
  documentsClosed: number;
  peersConnected: number;
  peersDisconnected: number;
}
