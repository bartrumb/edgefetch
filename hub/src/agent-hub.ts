export type FetchTarget = 'auto' | 'container' | 'agent';

export interface AgentAttachment {
  siteId: string;
  arch: string;
  connectedAt: number;
  lastJobAt: number;
  jobsOk: number;
  jobsErr: number;
  replaced?: boolean;
}

export interface AffinityPin {
  host: string;
  siteId: string;
  expiresAt: number;
}
