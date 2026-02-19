import { ThresholdAuthorizer } from '../src/threshold-auth.js';

const approvers = ['alice', 'bob', 'charlie'];

describe('ThresholdAuthorizer', () => {
  it('enforces K >= 2 (P2)', () => {
    expect(() => new ThresholdAuthorizer(1, approvers)).toThrow();
  });

  it('approves when threshold reached (P1)', () => {
    const auth = new ThresholdAuthorizer(2, approvers);
    const req = auth.createRequest('deploy to production', 'agent-1');
    auth.submitVote(req.requestId, 'alice', true);
    const result = auth.submitVote(req.requestId, 'bob', true);
    expect(result.status).toBe('approved');
    expect(auth.isApproved(req.requestId)).toBe(true);
  });

  it('denies early when threshold unreachable (P3)', () => {
    const auth = new ThresholdAuthorizer(2, approvers); // K=2, N=3, deny > N-K = 1 needed
    const req = auth.createRequest('rm -rf', 'agent-1');
    auth.submitVote(req.requestId, 'alice', false);
    const result = auth.submitVote(req.requestId, 'bob', false); // 2 denials > (3-2)=1
    expect(result.status).toBe('denied');
    expect(auth.isDenied(req.requestId)).toBe(true);
  });

  it('resolution is immutable once set (P4)', () => {
    const auth = new ThresholdAuthorizer(2, approvers);
    const req = auth.createRequest('action', 'agent-1');
    auth.submitVote(req.requestId, 'alice', true);
    auth.submitVote(req.requestId, 'bob', true);
    expect(auth.isApproved(req.requestId)).toBe(true);
    expect(() => auth.submitVote(req.requestId, 'charlie', false)).toThrow(); // already resolved (P4)
  });

  it('rejects double voting', () => {
    const auth = new ThresholdAuthorizer(2, approvers);
    const req = auth.createRequest('action', 'agent-1');
    auth.submitVote(req.requestId, 'alice', true);
    expect(() => auth.submitVote(req.requestId, 'alice', false)).toThrow();
  });

  it('rejects unregistered approver', () => {
    const auth = new ThresholdAuthorizer(2, approvers);
    const req = auth.createRequest('action', 'agent-1');
    expect(() => auth.submitVote(req.requestId, 'mallory', true)).toThrow();
  });
});
