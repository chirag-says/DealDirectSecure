import { Redirect, useLocalSearchParams } from 'expo-router';

/**
 * `/(tabs)/properties` — kept as a redirect, not deleted.
 *
 * Search moved to the first tab on 2026-08-24 and this path stopped being a
 * destination. It stays because `dealdirect://properties?...` links are
 * already in the wild, and because this is the one redirect in the app that
 * carries state: the affordability tool, the saved-search rows and the
 * collection rails all arrive with criteria in the query string.
 *
 * So the params are forwarded verbatim rather than dropped. A redirect that
 * silently discards `?priceBand=…` would land the user on the unfiltered
 * corpus, which looks like the feature working and is the worst kind of
 * broken. `SearchScreen` validates every param it reads, so forwarding
 * unvalidated values on is safe here.
 */
export default function PropertiesRedirect() {
  const params = useLocalSearchParams();

  return <Redirect href={{ pathname: '/(tabs)/search', params }} />;
}
