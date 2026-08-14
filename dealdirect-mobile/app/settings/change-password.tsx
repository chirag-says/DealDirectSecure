import Ionicons from '@expo/vector-icons/Ionicons';
import { useRouter } from 'expo-router';
import { useState } from 'react';
import { ScrollView, View } from 'react-native';

import { ApiError } from '@/api';
import { useChangePassword } from '@/features/profile';
import { useTheme } from '@/theme';
import { Button, Input, KeyboardAvoider, Screen, ScreenHeader, Text } from '@/ui';

export default function ChangePasswordScreen() {
  const router = useRouter();
  const theme = useTheme();
  const { changePassword, isPending, error, reset } = useChangePassword();

  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [localError, setLocalError] = useState<string | null>(null);
  const [done, setDone] = useState(false);

  const handleSubmit = async () => {
    setLocalError(null);
    reset();

    if (newPassword.length < 8) {
      setLocalError('New password must be at least 8 characters.');
      return;
    }
    if (newPassword !== confirmPassword) {
      setLocalError('Passwords do not match.');
      return;
    }

    try {
      await changePassword({ currentPassword, newPassword });
      setDone(true);
    } catch {
      // surfaced via `error` below
    }
  };

  return (
    <Screen>
      <ScreenHeader title="Change password" />

      <KeyboardAvoider className="flex-1">
        <ScrollView contentContainerStyle={{ padding: 24 }} keyboardShouldPersistTaps="handled">
          {done ? (
            <View className="items-center py-2xl">
              <Ionicons name="checkmark-circle" size={48} color={theme.colors.success} />
              <Text variant="title3" className="mt-base text-center">
                Password changed
              </Text>
              <Button label="Done" className="mt-lg" onPress={() => router.back()} />
            </View>
          ) : (
            <>
              <Input
                label="Current password"
                secureTextEntry
                autoCapitalize="none"
                textContentType="password"
                value={currentPassword}
                onChangeText={setCurrentPassword}
              />
              <Input
                label="New password"
                secureTextEntry
                autoCapitalize="none"
                textContentType="newPassword"
                value={newPassword}
                onChangeText={setNewPassword}
                containerClassName="mt-base"
                hint="At least 8 characters."
              />
              <Input
                label="Confirm new password"
                secureTextEntry
                autoCapitalize="none"
                textContentType="newPassword"
                value={confirmPassword}
                onChangeText={setConfirmPassword}
                containerClassName="mt-base"
              />

              {localError || error instanceof ApiError ? (
                <Text variant="footnote" tone="danger" className="mt-base">
                  {localError ?? (error as ApiError).message}
                </Text>
              ) : null}

              <Button
                label="Update password"
                className="mt-xl"
                loading={isPending}
                disabled={!currentPassword || !newPassword || !confirmPassword}
                onPress={() => void handleSubmit()}
              />
            </>
          )}
        </ScrollView>
      </KeyboardAvoider>
    </Screen>
  );
}
