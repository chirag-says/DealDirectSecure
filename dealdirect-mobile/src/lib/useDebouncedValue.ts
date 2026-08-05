import { useEffect, useState } from 'react';

/**
 * Trailing-edge debounce for a changing value.
 *
 * Used to keep typing off the network. `/properties/suggestions` and
 * `/properties/search` both sit behind the 20-requests-per-minute search
 * limiter, which is keyed on IP; on Indian carrier NAT that budget is shared
 * with strangers, so a request per keystroke is not merely wasteful, it takes
 * the endpoint away from other users.
 */
export function useDebouncedValue<T>(value: T, delayMs: number): T {
  const [debounced, setDebounced] = useState(value);

  useEffect(() => {
    const timer = setTimeout(() => setDebounced(value), delayMs);
    return () => clearTimeout(timer);
  }, [value, delayMs]);

  return debounced;
}
