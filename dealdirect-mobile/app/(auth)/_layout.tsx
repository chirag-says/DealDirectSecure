import { Stack } from 'expo-router';

/**
 * Auth group.
 *
 * Headerless: each auth screen carries its own title and back affordance so the
 * spacing stays under the screen's control rather than a shared bar's.
 *
 * `gestureEnabled: false` on the OTP step is deliberate. Swiping back from OTP
 * would strand a created-but-unverified account, and the user would hit "email
 * already registered" on retry. The screen provides an explicit way back that
 * resets the flow properly.
 */
export default function AuthLayout() {
  return (
    <Stack screenOptions={{ headerShown: false }}>
      <Stack.Screen name="login" />
      <Stack.Screen name="register" />
      <Stack.Screen name="verify-otp" options={{ gestureEnabled: false }} />
      <Stack.Screen name="forgot-password" />
    </Stack>
  );
}
