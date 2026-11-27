/**
 * Whether this build answers `streetcryptid://dev?cmd=…`.
 *
 * Only a dev build or a developer-telemetry build (`EXPO_PUBLIC_DEV_TELEMETRY=1`). The harness that
 * drives the channel reads its acknowledgement from the event log, which exists only in those
 * builds anyway (`metro.config.js` strips it otherwise), so a store build gains nothing from it —
 * and any web page or app that can open a URL could make a store build dial the stash and every
 * friend on demand.
 *
 * Both halves are read STATICALLY (the `stash-config.ts` convention): Babel inlines the
 * `EXPO_PUBLIC_*` value and `__DEV__` at build time, so in a store build this is the literal
 * `false` and the minifier drops what it guards. A dynamic read would silently be `undefined` in a
 * Hermes release build.
 */
export const DEV_COMMANDS_ENABLED: boolean =
  __DEV__ || process.env.EXPO_PUBLIC_DEV_TELEMETRY === '1';
