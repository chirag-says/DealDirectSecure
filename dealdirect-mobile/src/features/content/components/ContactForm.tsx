import { useMutation } from '@tanstack/react-query';
import { useState } from 'react';
import { StyleSheet, View } from 'react-native';

import { ApiError, call, contactEndpoints } from '@/api';
import { SignInPrompt, useAuth } from '@/auth';
import { radius, spacing, useTheme } from '@/theme';
import type { CreateInquiryRequest } from '@/types/backend/misc';
import { Button, Input, Select, Text, useToast } from '@/ui';

/**
 * The contact page's message form. `POST /contact`, which needs a session.
 *
 * A guest sees the sign-in prompt in the form's place rather than a form that
 * fails on send: the website does the same, and the reply goes to the email on
 * the account, so there is nothing to type for a name or an address. The rest
 * of the contact page (office, hours, phone, email) is above this and works
 * signed out, so a person with a problem is never stuck behind the gate.
 *
 * Categories are the website's seven, verbatim, because the admin inbox
 * filters on them.
 */

const CATEGORIES = [
  { value: 'general', label: 'General inquiry' },
  { value: 'property', label: 'Property related' },
  { value: 'partnership', label: 'Partnership' },
  { value: 'support', label: 'Technical support' },
  { value: 'feedback', label: 'Feedback' },
  { value: 'complaint', label: 'Complaint' },
  { value: 'other', label: 'Other' },
] as const;

type Category = (typeof CATEGORIES)[number]['value'];

const SUBJECT_MAX = 150;
const MESSAGE_MAX = 2000;

export function ContactForm() {
  const { status, user } = useAuth();
  const toast = useToast();
  const theme = useTheme();

  const [subject, setSubject] = useState('');
  const [category, setCategory] = useState<Category>('general');
  const [message, setMessage] = useState('');
  const [errors, setErrors] = useState<{ subject?: string; message?: string }>({});
  const [sent, setSent] = useState(false);

  const mutation = useMutation({
    mutationFn: (data: CreateInquiryRequest) => call(contactEndpoints.create, { data }),
  });

  if (status === 'restoring') return null;

  if (status === 'guest' || !user) {
    return (
      <SignInPrompt
        compact
        icon="chatbubble-ellipses-outline"
        title="Send us a message"
        description="Sign in first, so our reply reaches the email on your account."
      />
    );
  }

  if (sent) {
    return (
      <View
        style={{
          backgroundColor: theme.colors.successMuted,
          borderRadius: radius.lg,
          padding: spacing.base,
          gap: spacing.sm,
        }}
      >
        <Text variant="title3">Message sent</Text>
        <Text variant="body" tone="secondary">
          Our support team will reply to {user.email} shortly.
        </Text>
        <View style={{ marginTop: spacing.sm }}>
          <Button label="Send another" variant="secondary" onPress={() => setSent(false)} />
        </View>
      </View>
    );
  }

  const submit = async () => {
    const trimmedSubject = subject.trim();
    const trimmedMessage = message.trim();
    const nextErrors: typeof errors = {};
    if (!trimmedSubject) nextErrors.subject = 'Give your message a subject.';
    if (!trimmedMessage) nextErrors.message = 'Write a message first.';
    setErrors(nextErrors);
    if (nextErrors.subject || nextErrors.message) return;

    try {
      await mutation.mutateAsync({ subject: trimmedSubject, message: trimmedMessage, category });
      setSubject('');
      setMessage('');
      setCategory('general');
      setSent(true);
    } catch (error) {
      if (error instanceof ApiError && error.kind === 'rateLimited') {
        toast.show('Too many messages. Please wait a few minutes and try again.', 'danger');
        return;
      }
      toast.show(
        error instanceof ApiError ? error.message : 'Could not send your message. Please try again.',
        'danger'
      );
    }
  };

  return (
    <View>
      {/* The same rule-and-heading the page's sections use, so the form reads
          as one more section and not as a widget dropped under them. */}
      <View
        style={{
          height: StyleSheet.hairlineWidth,
          backgroundColor: theme.colors.border,
          marginBottom: spacing.lg,
        }}
      />
      <View style={{ marginBottom: spacing.base, gap: spacing.xs }}>
        <Text variant="title2">Send us a message</Text>
        <Text variant="callout" tone="muted">
          Got a question about a property, or want to partner with us? We will reply to {user.email}.
        </Text>
      </View>

      <View>
        <Input
          label="Subject"
          placeholder="Regarding a listing, a partnership…"
          value={subject}
          onChangeText={(value) => {
            setSubject(value);
            if (errors.subject) setErrors((current) => ({ ...current, subject: undefined }));
          }}
          maxLength={SUBJECT_MAX}
          error={errors.subject}
        />
        <Select
          label="Category"
          value={category}
          options={CATEGORIES}
          onChange={setCategory}
        />
        <Input
          label="Message"
          placeholder="How can we help you today?"
          value={message}
          onChangeText={(value) => {
            setMessage(value);
            if (errors.message) setErrors((current) => ({ ...current, message: undefined }));
          }}
          multiline
          numberOfLines={5}
          maxLength={MESSAGE_MAX}
          error={errors.message}
          hint={
            message.length > 0
              ? `${message.length.toLocaleString('en-IN')}/${MESSAGE_MAX.toLocaleString('en-IN')}`
              : undefined
          }
        />
        <Button
          label="Send message"
          fullWidth
          loading={mutation.isPending}
          onPress={() => void submit()}
        />
      </View>
    </View>
  );
}
