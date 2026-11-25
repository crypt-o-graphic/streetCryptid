import type { ProfileView } from 'iroh-location';

import { MAX_FRIEND_NAME_CODE_POINTS, sanitizeDisplayText } from '../display-text';
import { mergeProfileIntoFriend } from '../profile';
import type { Friend } from '../types';

// Escapes only: a literal bidi control in a test file is the spoof aimed at its reader.
const RLO = '\u202E';
const LRI = '\u2066';
const PDI = '\u2069';
const ZWJ = '\u200D';
const ZWNJ = '\u200C';
const WOMAN = '\u{1F469}';
const GIRL = '\u{1F467}';
const BAT = '\u{1F987}';

describe('sanitizeDisplayText', () => {
  it('strips every bidi control', () => {
    const controls = ['\u061C', '\u200E', '\u200F', '\u202A', '\u202B', '\u202C', '\u202D'];
    controls.push(RLO, LRI, '\u2067', '\u2068', PDI);
    expect(sanitizeDisplayText(`a${controls.join('')}b`, 64)).toBe('ab');
    // The spoof itself: an override that would draw "gpj.exe" as "exe.jpg".
    expect(sanitizeDisplayText(`moth${RLO}gpj.exe`, 64)).toBe('mothgpj.exe');
  });

  it('strips C0 and C1 controls, DEL, line separators and invisible characters', () => {
    expect(sanitizeDisplayText('a\u0000b\u0007c\u007Fd\u0085e\u009Ff', 64)).toBe('abcdef');
    expect(sanitizeDisplayText('one\u2028two\u2029three', 64)).toBe('onetwothree');
    expect(sanitizeDisplayText('in\u200Bvis\u2060ib\uFEFFle\u00AD', 64)).toBe('invisible');
    expect(sanitizeDisplayText('\u3164\u115F', 64)).toBe('');
  });

  it('collapses whitespace and trims', () => {
    expect(sanitizeDisplayText('  big \t \n  foot  ', 64)).toBe('big foot');
  });

  it('keeps joiners that join, and drops runs and stranded ones', () => {
    const family = `${WOMAN}${ZWJ}${WOMAN}${ZWJ}${GIRL}`;
    expect(sanitizeDisplayText(family, 64)).toBe(family);
    const persian = `\u0645\u06CC${ZWNJ}\u062E\u0648\u0627\u0647\u0645`;
    expect(sanitizeDisplayText(persian, 64)).toBe(persian);
    expect(sanitizeDisplayText(`${ZWJ}a${ZWJ}${ZWJ}${ZWJ}b${ZWNJ}`, 64)).toBe(`a${ZWJ}b`);
  });

  it('clamps by code point without splitting a surrogate pair', () => {
    const out = sanitizeDisplayText(BAT.repeat(100), 5);
    expect(Array.from(out)).toHaveLength(5);
    expect(out).toBe(BAT.repeat(5));
  });

  it('leaves ordinary names alone', () => {
    expect(sanitizeDisplayText('Wayward Kappa', 32)).toBe('Wayward Kappa');
    expect(sanitizeDisplayText('\u014Ckami \u72FC', 32)).toBe('\u014Ckami \u72FC');
  });
});

describe('mergeProfileIntoFriend cleans the peer text', () => {
  const friend = {
    endpointId: 'peer',
    handle: '@old',
    sigil: 'sigil',
    recvPublic: 'recv',
    ticket: 'ticket',
    cryptidName: 'Old Name',
    profileEpoch: 1,
  } as Friend;

  function profile(overrides: Partial<ProfileView>): ProfileView {
    return {
      endpointId: 'peer',
      epoch: 2,
      handle: '@peer',
      cryptidName: 'Peer',
      sigil: 'sigil',
      color: '#123456',
      recvPub: 'recv',
      ts: 2,
      ...overrides,
    };
  }

  it('strips controls and clamps the cryptid name and handle', () => {
    const merged = mergeProfileIntoFriend(
      friend,
      profile({
        cryptidName: `${RLO}Moth${LRI}man${PDI}${'x'.repeat(500)}`,
        handle: `@moth${RLO}\u0000`,
      })
    );
    expect(merged.cryptidName?.startsWith('Mothman')).toBe(true);
    expect(Array.from(merged.cryptidName ?? '')).toHaveLength(MAX_FRIEND_NAME_CODE_POINTS);
    expect(merged.handle).toBe('@moth');
  });

  it('keeps the old values when the new ones clean to nothing', () => {
    const merged = mergeProfileIntoFriend(
      friend,
      profile({ cryptidName: `${RLO}${ZWJ}\u200B`, handle: '\u202A\u202C' })
    );
    expect(merged.cryptidName).toBe('Old Name');
    expect(merged.handle).toBe('@old');
    expect(merged.profileEpoch).toBe(2);
  });
});
