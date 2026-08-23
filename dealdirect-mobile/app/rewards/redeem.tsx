import { useRouter } from 'expo-router';
import { useCallback, useEffect, useRef, useState } from 'react';
import { BackHandler, Linking, View } from 'react-native';
import {
  WebView,
  type WebViewMessageEvent,
  type WebViewNavigation,
} from 'react-native-webview';

import { RequireAuth } from '@/auth';
import { HUBBLE_INTERNAL_URL, useHubbleSession } from '@/features/rewards';
import { useTheme } from '@/theme';
import { EmptyState, ErrorState, Screen, ScreenHeader, Skeleton } from '@/ui';

/**
 * Rewards redemption — the Hubble gift-card SDK, hosted in a WebView.
 *
 * ---------------------------------------------------------------------------
 * WHY A WEBVIEW AT ALL
 *
 * Redemption spends real money and is the one flow in this app the backend does
 * not own end to end. Hubble holds the catalogue, the payment step and the
 * fulfilment; the wallet is debited by Hubble calling our backend
 * server-to-server with a shared secret, not by anything this screen does. So
 * there is no native surface to build — the SDK IS the feature, and the app's
 * job is to host it, hand it a valid session, and get out of the way.
 *
 * ---------------------------------------------------------------------------
 * THIS WEBVIEW MUST NEVER CALL THE DEALDIRECT API
 *
 * `api/client.ts` carries the constraint in full: `requireCsrf` waves through
 * any request with no `Origin` header, which is why the native client is exempt
 * from CSRF — and a WebView is exactly the thing that DOES attach an `Origin`.
 * Twelve write routes would answer `CSRF_ORIGIN_REJECTED`.
 *
 * This screen is compliant by construction. It loads `sdk.myhubble.money`, a
 * different origin that carries no DealDirect cookie, and the session it needs
 * is fetched NATIVELY and passed in through the URL. Nothing inside the WebView
 * ever talks to our API. Keep it that way.
 */
export default function RedeemRoute() {
  return (
    <RequireAuth
      title="Redeem points"
      promptTitle="Sign in to redeem"
      promptDescription="Your points balance belongs to your account, so redeeming needs you signed in."
      icon="gift-outline"
      backTo="/rewards"
    >
      <RedeemScreen />
    </RequireAuth>
  );
}

function RedeemScreen() {
  const router = useRouter();
  const theme = useTheme();
  const webViewRef = useRef<WebView>(null);

  const { url, isLoading, unavailable, error, retry } = useHubbleSession();

  // Two different waits. `isLoading` is us fetching the session; `ready` is the
  // SDK telling us it has finished booting. Showing the WebView between the two
  // would show the user a blank white rectangle.
  const [ready, setReady] = useState(false);
  const [sdkFailed, setSdkFailed] = useState(false);
  const [canGoBack, setCanGoBack] = useState(false);

  const leave = useCallback(() => {
    if (router.canGoBack()) router.back();
    else router.replace('/rewards');
  }, [router]);

  /**
   * Android hardware back walks the SDK's own history first.
   *
   * Without this, back exits the whole flow from any depth — including from the
   * middle of a payment — which is both jarring and, mid-transaction, genuinely
   * risky.
   */
  useEffect(() => {
    const onBack = () => {
      if (canGoBack && webViewRef.current) {
        webViewRef.current.goBack();
        return true;
      }
      return false;
    };
    const subscription = BackHandler.addEventListener('hardwareBackPress', onBack);
    return () => subscription.remove();
  }, [canGoBack]);

  /**
   * Keep Hubble and Razorpay inside; hand everything else to the OS.
   *
   * That "everything else" is the point of the whole handler: `upi://`,
   * `phonepe://`, `tez://` and the rest are how a payment actually completes.
   * A WebView cannot open them, so they have to leave — and the matching is on
   * HOST, not on the SDK base URL, because Razorpay is a different domain and
   * sending it out breaks the flow silently: the user pays in the system
   * browser and the SDK never sees the result.
   */
  const handleNavigation = useCallback((request: WebViewNavigation) => {
    if (HUBBLE_INTERNAL_URL.test(request.url)) return true;

    Linking.openURL(request.url).catch(() => {
      // No app installed to handle it — a UPI app the user does not have.
      // Silent by design: the SDK still offers the other payment methods, and
      // an error here would be about a choice the user has not made yet.
    });
    return false;
  }, []);

  /**
   * The SDK's only channel back to us.
   *
   * `close` matters most: it is the sole way the SDK says the user wants out,
   * and not handling it strands them inside a flow with no exit. There is a
   * native header here as well, deliberately — if the SDK fails before it can
   * emit anything, that header is the only way back.
   */
  const handleMessage = useCallback(
    (event: WebViewMessageEvent) => {
      let payload: { type?: string; action?: string } | null = null;
      try {
        payload = JSON.parse(event.nativeEvent.data);
      } catch {
        // The SDK is not the only thing that can post a message into a
        // WebView. Anything unparseable is not ours to act on.
        return;
      }
      if (!payload || typeof payload !== 'object') return;

      if (payload.type === 'action') {
        if (payload.action === 'app_ready') setReady(true);
        else if (payload.action === 'close') leave();
        else if (payload.action === 'error') setSdkFailed(true);
      }

      // Analytics events are received and dropped. This app has no analytics
      // provider wired up; forwarding them nowhere would be theatre.
    },
    [leave]
  );

  const showSpinner = (isLoading || !ready) && !sdkFailed && !unavailable && !error;

  return (
    <Screen edges={['top', 'bottom']}>
      <ScreenHeader title="Redeem points" backTo="/rewards" />

      {unavailable ? (
        <EmptyState
          title="Redemption is unavailable"
          description="Rewards redemption is not switched on for this build yet. Your points are safe and still earning."
          actionLabel="Back to rewards"
          onAction={leave}
        />
      ) : error || sdkFailed ? (
        <ErrorState
          title="Could not open redemption"
          description={
            sdkFailed
              ? 'The rewards partner could not start a session. Please try again in a moment.'
              : (error?.message ?? 'Please check your connection and try again.')
          }
          onRetry={() => {
            setSdkFailed(false);
            setReady(false);
            retry();
          }}
        />
      ) : (
        <View className="flex-1">
          {url ? (
            <WebView
              ref={webViewRef}
              source={{ uri: url }}
              javaScriptEnabled
              domStorageEnabled
              startInLoadingState
              setSupportMultipleWindows
              javaScriptCanOpenWindowsAutomatically
              // A fresh session every time. The SSO token is single-use, so a
              // cached document would replay a spent credential.
              cacheEnabled={false}
              incognito
              onShouldStartLoadWithRequest={handleNavigation}
              onMessage={handleMessage}
              onNavigationStateChange={(navState) => setCanGoBack(navState.canGoBack)}
              onError={() => setSdkFailed(true)}
              onHttpError={() => setSdkFailed(true)}
              style={{ flex: 1, backgroundColor: theme.colors.background }}
            />
          ) : null}

          {/*
            Covers the WebView until the SDK reports `app_ready`. Absolutely
            positioned rather than rendered instead of the WebView, because the
            WebView has to be mounted and loading for `app_ready` to ever
            arrive.
          */}
          {showSpinner ? (
            <View
              className="absolute inset-0 p-base"
              style={{ backgroundColor: theme.colors.background }}
            >
              <Skeleton height={72} radius={16} className="mb-base" />
              <Skeleton height={180} radius={16} className="mb-base" />
              <Skeleton height={180} radius={16} />
            </View>
          ) : null}
        </View>
      )}
    </Screen>
  );
}
