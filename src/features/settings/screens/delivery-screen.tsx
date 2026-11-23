import { useMemo, useState } from 'react';
import type { Href } from 'expo-router';
import { type DataMode, tryGetIrohLocation } from 'iroh-location';
import { useColorScheme } from '@/hooks/use-color-scheme';
import { ThemedText } from '@/components/themed-text';
import { CryptidThemes } from '@/constants/theme';
import type { DeliveryAvailability, DeliveryMode } from '@/features/social/core/delivery-mode';
import { useLocationSharing } from '@/features/social/hooks/use-location-sharing';

import { DataModeControls } from '../components/data-mode-controls';
import { DeliveryOptions } from '../components/delivery-options';
import { LocationAccessRow } from '../components/location-access-row';
import { SettingsMenuRow } from '../components/settings-menu-row';
import { SettingsPage, SettingsSection } from '../components/settings-page';

export default function DeliveryScreen() {
  const scheme = useColorScheme();
  const chrome = CryptidThemes[scheme === 'dark' ? 'deepsea' : 'daybreak'].chrome;
  const { snapshot, setDeliveryMode, disclosureStatus, acknowledgeLocationDisclosure } =
    useLocationSharing();
  const availability = useMemo<DeliveryAvailability>(
    () => ({ stashConfigured: snapshot?.delivery.stashConfigured ?? false }),
    [snapshot?.delivery.stashConfigured]
  );
  const [pending, setPending] = useState<DeliveryMode | null>(null);
  const [error, setError] = useState<string | null>(null);
  const selected = pending ?? snapshot?.delivery.mode ?? 'mutual';
  const [dataMode, setDataModeState] = useState<DataMode | null>(readDataMode);
  const [dataModeBusy, setDataModeBusy] = useState(false);

  async function selectDataMode(mode: DataMode) {
    const native = tryGetIrohLocation();
    if (typeof native?.setDataMode !== 'function') return;
    setDataModeBusy(true);
    setError(null);
    try {
      await native.setDataMode(mode);
      setDataModeState(mode);
    } catch {
      setError('Could not save the data use setting. Try again.');
    } finally {
      setDataModeBusy(false);
    }
  }

  async function select(mode: DeliveryMode) {
    setPending(mode);
    setError(null);
    try {
      await setDeliveryMode(mode);
    } catch {
      setError('Could not save the delivery mode. Try again.');
    } finally {
      setPending(null);
    }
  }

  return (
    <SettingsPage title="Delivery">
      <DeliveryOptions
        selected={selected}
        availability={availability}
        disabled={pending !== null}
        onSelect={(mode) => void select(mode)}
        footnote={
          <SettingsMenuRow
            href={'/settings/repeaters' as Href}
            label="Repeaters"
            value="Your own, and friends'"
          />
        }
      />
      {error ? (
        <ThemedText accessibilityRole="alert" type="small">
          {error}
        </ThemedText>
      ) : null}
      {dataMode !== null ? (
        <SettingsSection label="DATA USE">
          <DataModeControls
            accent={chrome.green}
            selected={dataMode}
            disabled={dataModeBusy}
            hasCarrier={selected === 'stash' && availability.stashConfigured}
            onSelect={(mode) => void selectDataMode(mode)}
          />
        </SettingsSection>
      ) : null}
      <SettingsSection label="ACCESS">
        <LocationAccessRow
          accent={chrome.amber}
          status={disclosureStatus}
          onTurnOn={() => void acknowledgeLocationDisclosure(true)}
        />
      </SettingsSection>
    </SettingsPage>
  );
}

/** The node's data mode, or `null` where there is no node to ask (web, an older binary). */
function readDataMode(): DataMode | null {
  try {
    return tryGetIrohLocation()?.dataMode?.() ?? null;
  } catch {
    return null;
  }
}
