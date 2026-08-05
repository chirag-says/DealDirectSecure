import type { AxiosRequestConfig } from 'axios';

import type { Endpoint } from './endpoints/_contract';
import { apiClient, uploadClient } from './client';

/**
 * Typed endpoint caller.
 *
 * The glue between the M0 endpoint descriptors and axios. Callers name an
 * endpoint rather than a URL, so a path exists in exactly one place and its
 * request and response types come along automatically.
 *
 * All three type parameters are inferred from the endpoint. They are NOT
 * constrained to `Endpoint<unknown, unknown, unknown>`: `EndpointSpec.path` is a
 * conditional type keyed on the path-params parameter, which makes a wildcard
 * in that position fail to match every endpoint declared with a static string
 * path.
 *
 * Query params are serialised with axios's default behaviour, which does NOT
 * repeat a key. That matters: `server.js` mounts `hpp` with a whitelist of
 * sort/fields/page/limit/status/type, and any other repeated parameter is
 * collapsed to a single value. A naive `amenities=a&amenities=b` would silently
 * lose data, so repeated params must never be sent outside that whitelist.
 */

export interface CallOptions<TRequest, TPathParams> {
  /** Path parameters, when the endpoint declares them. */
  params?: TPathParams;
  /** Query string for GET, request body for every other method. */
  data?: TRequest;
  signal?: AbortSignal;
  onUploadProgress?: AxiosRequestConfig['onUploadProgress'];
}

/**
 * Calls an endpoint and returns its raw body.
 *
 * The body is returned UNCHANGED, in whichever of the backend's six envelopes
 * that endpoint uses. Unwrapping is each feature adapter's job, because there
 * is no shape common to all of them: `/properties/search` has no `success` key
 * at all, and `/properties/:id` has no envelope whatsoever.
 */
export async function call<TRequest, TResponse, TPathParams>(
  endpoint: Endpoint<TRequest, TResponse, TPathParams>,
  options: CallOptions<TRequest, TPathParams> = {}
): Promise<TResponse> {
  const { params, data, signal, onUploadProgress } = options;

  // `path` is a conditional type, so it needs narrowing by hand: TypeScript
  // will not resolve it against an unresolved type parameter.
  const { path } = endpoint;
  const url: string =
    typeof path === 'function'
      ? (path as (p: TPathParams) => string)(params as TPathParams)
      : (path as string);

  const isRead = endpoint.method === 'GET';
  const isMultipart = typeof FormData !== 'undefined' && data instanceof FormData;
  const client = isMultipart ? uploadClient : apiClient;

  const response = await client.request<TResponse>({
    url,
    method: endpoint.method,
    ...(isRead ? { params: data } : { data }),
    ...(signal ? { signal } : {}),
    ...(onUploadProgress ? { onUploadProgress } : {}),
  });

  return response.data;
}
