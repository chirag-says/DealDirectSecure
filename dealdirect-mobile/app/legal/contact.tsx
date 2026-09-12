import { ContactForm, ContentPageView, contactPage } from '@/features/content';

/**
 * Contact: the office, the hours, the phone and email, and a message form.
 *
 * A static route so it wins over `[id]` for `/legal/contact`. The static half
 * is data like every other page; the form is the one piece of content in this
 * directory that needs a session and a mutation, and it renders below.
 */
export default function ContactScreen() {
  return (
    <ContentPageView page={contactPage}>
      <ContactForm />
    </ContentPageView>
  );
}
