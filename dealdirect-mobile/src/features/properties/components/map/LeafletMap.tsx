import type * as WebViewModule from 'react-native-webview';
import { useCallback, useMemo, useRef } from 'react';
import { View } from 'react-native';

import { optionalNativeModule } from '@/config/optionalNative';
import { useTheme } from '@/theme';
import { buildMapHtml, type MapMarker } from './leafletHtml';

/**
 * A Leaflet map, hosted in a WebView, with a typed bridge.
 *
 * The WebView is presentational — see `leafletHtml.ts` for why that is a
 * security invariant, not a style choice. This component owns the RN side of
 * the protocol: it builds the document once, pushes markers and camera commands
 * in, and turns messages out into typed callbacks.
 *
 * `react-native-webview` is loaded optionally. It is a real dependency of the
 * app, but loading it through the same guard as every other native module means
 * a host without it (Expo Go) renders the fallback rather than crashing the
 * screen — and the map is exactly the kind of screen that should degrade to
 * "not here" rather than take the route down with it.
 */

const WebViewMod = optionalNativeModule(
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  () => require('react-native-webview') as typeof WebViewModule,
  'react-native-webview',
  'The map needs a full build of the app; it is not available in Expo Go.',
);

export const mapAvailable = WebViewMod !== null;

interface BridgeMessage {
  type: 'ready' | 'markerPress' | 'viewDetails' | 'mapPress' | 'tileError';
  id?: string;
  lat?: number;
  lng?: number;
}

export interface LeafletMapProps {
  markers: readonly MapMarker[];
  mode: 'detail' | 'search';
  center?: { lat: number; lng: number; zoom?: number };
  selectedId?: string | null;
  /** Fit all markers into view once loaded. Search uses this; detail centres. */
  fitOnReady?: boolean;
  onMarkerPress?: (id: string) => void;
  onViewDetails?: (id: string) => void;
  onMapPress?: (lat: number, lng: number) => void;
  onReady?: () => void;
  /** Rendered when the WebView module is absent. */
  fallback?: React.ReactNode;
  style?: object;
}

export function LeafletMap({
  markers,
  mode,
  center,
  selectedId,
  fitOnReady,
  onMarkerPress,
  onViewDetails,
  onMapPress,
  onReady,
  fallback,
  style,
}: LeafletMapProps) {
  const theme = useTheme();
  const ref = useRef<WebViewModule.WebView>(null);

  const html = useMemo(
    () =>
      buildMapHtml({
        center,
        mode,
        brand: theme.colors.brand,
        surface: theme.colors.surface,
        text: theme.colors.textPrimary,
      }),
    // The document is built ONCE. Marker and camera changes go over the bridge,
    // never by rebuilding the HTML, which would reload the whole map and lose
    // its state. Only a theme flip or a mode change justifies a rebuild.
    [mode, theme.colors.brand, theme.colors.surface, theme.colors.textPrimary, center],
  );

  const send = useCallback((message: object) => {
    ref.current?.postMessage(JSON.stringify(message));
  }, []);

  const onMessage = useCallback(
    (event: WebViewModule.WebViewMessageEvent) => {
      let msg: BridgeMessage;
      try {
        msg = JSON.parse(event.nativeEvent.data) as BridgeMessage;
      } catch {
        return;
      }

      switch (msg.type) {
        case 'ready':
          // Push the initial data now that the map exists. Doing it here rather
          // than on an interval is why there is no race and no flash of an
          // empty map with a late marker pop-in.
          send({ type: 'setMarkers', markers });
          if (selectedId) send({ type: 'setSelected', id: selectedId });
          if (fitOnReady) send({ type: 'fitBounds' });
          onReady?.();
          break;
        case 'markerPress':
          if (msg.id) onMarkerPress?.(msg.id);
          break;
        case 'viewDetails':
          if (msg.id) onViewDetails?.(msg.id);
          break;
        case 'mapPress':
          if (typeof msg.lat === 'number' && typeof msg.lng === 'number') {
            onMapPress?.(msg.lat, msg.lng);
          }
          break;
        case 'tileError':
          // Left unhandled by design: one tile failing to load is not worth a
          // user-facing error, and the map is usable with a gap in it.
          break;
      }
    },
    [markers, selectedId, fitOnReady, send, onMarkerPress, onViewDetails, onMapPress, onReady],
  );

  if (!WebViewMod) {
    return <>{fallback ?? null}</>;
  }

  const WebView = WebViewMod.WebView;

  return (
    <View style={[{ flex: 1 }, style]}>
      <WebView
        ref={ref}
        originWhitelist={['*']}
        source={{ html }}
        onMessage={onMessage}
        // No API call ever originates here (see `leafletHtml.ts`), so a
        // WebView with broad content access carries no session risk — it holds
        // no cookie and makes no authenticated request.
        javaScriptEnabled
        domStorageEnabled={false}
        // The map draws its own background; a white flash on load is jarring
        // against a dark theme.
        style={{ flex: 1, backgroundColor: theme.colors.surface }}
        // Let the map own vertical drags; the parent scroll must not steal them.
        nestedScrollEnabled
      />
    </View>
  );
}

/**
 * Imperatively push new markers / camera to a mounted map.
 *
 * Exposed as a hook returning a ref-driven controller, for the search screen
 * where markers change as filters change and rebuilding the document each time
 * would reload the map. Not needed by the detail map, which is static.
 */
export type { MapMarker };
