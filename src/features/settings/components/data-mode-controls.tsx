import { Pressable, StyleSheet, View } from 'react-native';

import type { DataMode } from 'iroh-location';
import { ThemedText } from '@/components/themed-text';
import { Spacing } from '@/constants/theme';
import { useTheme } from '@/hooks/use-theme';

interface DataModeControlsProps {
  accent: string;
  selected: DataMode | null;
  disabled?: boolean;
  /** False without a stash or a repeater: friends' phones are then the only way, and are used. */
  hasCarrier: boolean;
  onSelect(mode: DataMode): void;
}

/**
 * How much mobile data the app may spend reaching friends' phones directly (`dial_gate.rs`).
 *
 * The stash and repeaters carry every fix whatever is chosen here. What changes is how often a
 * friend's phone is dialled directly, and how often dots refresh in the background. Those two were
 * nearly all of the 34 GB a week one Pixel uploaded on 2026-11-21: dials to friends' phones that
 * were asleep, and pulls nobody was looking at.
 */
export const DATA_MODES: { id: DataMode; label: string; detail: string }[] = [
  {
    id: 'saver',
    label: 'Saver',
    detail:
      "Never calls friends' phones over the internet. Your stash and repeaters carry everything, " +
      'and friends nearby on Bluetooth or the same Wi-Fi still update directly. Dots refresh ' +
      'when you open the app.',
  },
  {
    id: 'balanced',
    label: 'Balanced',
    detail:
      "Calls a friend's phone only when it was just active, so a friend you are watching " +
      'moves live. Everyone else comes through the stash. Dots refresh about hourly in the ' +
      'background. Recommended.',
  },
  {
    id: 'realtime',
    label: 'Real time',
    detail:
      "Calls every friend's phone on every update and keeps a live mesh open. Fastest when " +
      'both phones are awake. Uses many times the data and battery: best on Wi-Fi.',
  },
];

export function DataModeControls({
  accent,
  selected,
  disabled,
  hasCarrier,
  onSelect,
}: DataModeControlsProps) {
  const theme = useTheme();
  return (
    <View style={styles.wrap}>
      <View
        accessibilityRole="radiogroup"
        style={[styles.list, { borderColor: theme.backgroundSelected }]}
      >
        {DATA_MODES.map((mode, index) => {
          const checked = selected === mode.id;
          return (
            <Pressable
              key={mode.id}
              accessibilityRole="radio"
              accessibilityState={{ checked, disabled: disabled ?? false }}
              accessibilityLabel={`${mode.label} data use`}
              disabled={disabled}
              onPress={() => onSelect(mode.id)}
              style={[
                styles.row,
                index > 0 && {
                  borderTopColor: theme.backgroundSelected,
                  borderTopWidth: StyleSheet.hairlineWidth,
                },
              ]}
            >
              <View style={[styles.radio, { borderColor: checked ? accent : theme.textSecondary }]}>
                {checked ? <View style={[styles.dot, { backgroundColor: accent }]} /> : null}
              </View>
              <View style={styles.copy}>
                <ThemedText type="smallBold">{mode.label}</ThemedText>
                <ThemedText type="small" themeColor="textSecondary">
                  {mode.detail}
                </ThemedText>
              </View>
            </Pressable>
          );
        })}
      </View>
      {hasCarrier ? null : (
        <ThemedText type="small" themeColor="textSecondary">
          With no stash or repeater carrying your trail, friends&apos; phones are the only way to
          reach them, so they are called directly whatever you choose here.
        </ThemedText>
      )}
    </View>
  );
}

const styles = StyleSheet.create({
  wrap: { gap: Spacing.two },
  list: {
    borderRadius: Spacing.two,
    borderWidth: StyleSheet.hairlineWidth,
    overflow: 'hidden',
  },
  row: {
    alignItems: 'flex-start',
    flexDirection: 'row',
    gap: Spacing.three,
    padding: Spacing.three,
  },
  radio: {
    alignItems: 'center',
    borderRadius: 10,
    borderWidth: 2,
    height: 20,
    justifyContent: 'center',
    marginTop: 2,
    width: 20,
  },
  dot: { borderRadius: 5, height: 10, width: 10 },
  copy: { flex: 1, gap: Spacing.one },
});
