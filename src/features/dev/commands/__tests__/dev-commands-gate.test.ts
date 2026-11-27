/**
 * A store build (neither `__DEV__` nor `EXPO_PUBLIC_DEV_TELEMETRY=1`) must not answer the command
 * channel: any page or app can open `streetcryptid://dev?cmd=sync-trail`, and it would make the
 * app dial the stash and every friend on demand.
 */
jest.mock('../gate', () => ({ DEV_COMMANDS_ENABLED: false }));

// eslint-disable-next-line import/first
import { redirectSystemPath } from '@/app/+native-intent';

// eslint-disable-next-line import/first
import { runDevCommand } from '../dev-commands';

describe('dev command channel in a store build', () => {
  it('runs nothing', async () => {
    const syncTrail = jest.fn(async () => {});
    const trailReplicaStatus = jest.fn(async () => []);
    await runDevCommand('sync-trail', 'n1', { syncTrail, trailReplicaStatus });
    await runDevCommand('replica-status', 'n2', { syncTrail, trailReplicaStatus });
    expect(syncTrail).not.toHaveBeenCalled();
    expect(trailReplicaStatus).not.toHaveBeenCalled();
  });

  it('routes the deep link to the plain map', () => {
    expect(
      redirectSystemPath({ path: 'streetcryptid://dev?cmd=sync-trail&id=abc', initial: false })
    ).toBe('/');
  });
});
