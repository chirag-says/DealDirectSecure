/**
 * The map, as a self-contained HTML document for a WebView.
 *
 * ---------------------------------------------------------------------------
 * THE WEBVIEW IS PRESENTATIONAL, AND THAT IS A SECURITY INVARIANT
 *
 * This document renders a map and nothing else. It issues no API call, does no
 * geocoding, and holds no session. Every piece of data arrives from React
 * Native over `postMessage`, and every action it wants — open a listing, report
 * a tapped coordinate — leaves the same way. `client.ts` documents why: the
 * app's cookie session is bound to a constant User-Agent and the absence of an
 * `Origin` header, and a request originating inside a WebView would carry a
 * WebView's Origin and be refused by the 16 CSRF-guarded routes. So the WebView
 * must never be a place a request comes from. Keeping it dumb is what keeps that
 * true.
 *
 * ---------------------------------------------------------------------------
 * LEAFLET IS LOADED FROM A CDN, AND THAT IS A PILOT CHOICE
 *
 * The map spec (`docs/MAP_IMPLEMENTATION.md`) calls for Leaflet bundled as a
 * local asset for CDN-independence. For this first cut it loads from unpkg,
 * because the map cannot show tiles without a network anyway — the OSM tile
 * server is a network dependency the library load merely joins — so vendoring
 * Leaflet buys reliability against one CDN's downtime, not offline capability.
 * Vendoring is a clean follow-up: replace the two <link>/<script> tags with the
 * asset contents. Flagged rather than hidden.
 *
 * ---------------------------------------------------------------------------
 * THE PROTOCOL
 *
 * RN → WebView, as `postMessage(JSON)`:
 *   { type: 'setMarkers', markers: MapMarker[] }
 *   { type: 'setCenter', lat, lng, zoom? }
 *   { type: 'setSelected', id }
 *   { type: 'fitBounds' }
 *   { type: 'setPinDrop', enabled }
 *   { type: 'setPin', lat, lng }        place/move the pin without a tap
 *   { type: 'setRadius', km }        // draws a circle at the dropped pin
 *
 * WebView → RN, as `window.ReactNativeWebView.postMessage(JSON)`:
 *   { type: 'ready' }
 *   { type: 'markerPress', id }
 *   { type: 'viewDetails', id }
 *   { type: 'mapPress', lat, lng }
 *   { type: 'tileError' }
 */

export interface MapMarker {
  id: string;
  lat: number;
  lng: number;
  /** Rupees. Rendered as a price pill; see the pill formatter in the HTML. */
  price: number;
  intent: 'rent' | 'sale' | null;
  title: string;
  locationLabel: string;
}

export interface LeafletHtmlOptions {
  /** Initial centre. Defaults to the centre of India when absent. */
  center?: { lat: number; lng: number; zoom?: number };
  /** Detail: one static marker, no controls. Search: many, with controls. */
  mode: 'detail' | 'search';
  /** Theme colours, so the map matches the app in light and dark. */
  brand: string;
  surface: string;
  text: string;
}

const LEAFLET_VERSION = '1.9.4';

export function buildMapHtml(options: LeafletHtmlOptions): string {
  const center = options.center ?? { lat: 20.5937, lng: 78.9629, zoom: 5 };
  const initialZoom = center.zoom ?? (options.mode === 'detail' ? 15 : 11);

  // Serialised into the document so the map has its first centre before any
  // message arrives, and the detail map is never blank waiting for a round trip.
  const boot = JSON.stringify({
    mode: options.mode,
    center: { lat: center.lat, lng: center.lng, zoom: initialZoom },
    brand: options.brand,
    surface: options.surface,
    text: options.text,
  });

  return `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no" />
  <link rel="stylesheet" href="https://unpkg.com/leaflet@${LEAFLET_VERSION}/dist/leaflet.css" />
  <style>
    html, body, #map { height: 100%; margin: 0; padding: 0; background: ${options.surface}; }
    .price-pill {
      background: ${options.surface};
      color: ${options.text};
      border: 1px solid rgba(0,0,0,0.15);
      border-radius: 14px;
      padding: 3px 8px;
      font: 600 12px -apple-system, Roboto, sans-serif;
      white-space: nowrap;
      box-shadow: 0 1px 4px rgba(0,0,0,0.25);
      transform: translate(-50%, -100%);
    }
    .price-pill.selected { background: ${options.brand}; color: #fff; border-color: ${options.brand}; }
    .leaflet-popup-content-wrapper { border-radius: 12px; }
    .leaflet-popup-content { margin: 12px; font: 13px -apple-system, Roboto, sans-serif; }
    .popup-title { font-weight: 700; margin-bottom: 2px; }
    .popup-loc { color: #6b7280; margin-bottom: 6px; }
    .popup-btn {
      display: inline-block; background: ${options.brand}; color: #fff;
      border-radius: 8px; padding: 6px 12px; font-weight: 600; text-decoration: none;
    }
  </style>
</head>
<body>
  <div id="map"></div>
  <script src="https://unpkg.com/leaflet@${LEAFLET_VERSION}/dist/leaflet.js"></script>
  <script>
    (function () {
      var BOOT = ${boot};
      var post = function (msg) {
        if (window.ReactNativeWebView) window.ReactNativeWebView.postMessage(JSON.stringify(msg));
      };

      var map = L.map('map', { zoomControl: BOOT.mode === 'search', attributionControl: true })
        .setView([BOOT.center.lat, BOOT.center.lng], BOOT.center.zoom);
      if (BOOT.mode === 'search') { L.control.zoom({ position: 'bottomright' }).addTo(map); map.removeControl(map.zoomControl); }

      var tiles = L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
        maxZoom: 19,
        attribution: '&copy; OpenStreetMap contributors'
      });
      tiles.on('tileerror', function () { post({ type: 'tileError' }); });
      tiles.addTo(map);

      var markerLayer = L.layerGroup().addTo(map);
      var byId = {};
      var selectedId = null;
      var pinDrop = false;
      var pinMarker = null;
      var radiusCircle = null;

      function pill(price) {
        var t;
        if (price >= 1e7) t = '₹' + (price / 1e7).toFixed(1) + 'Cr';
        else if (price >= 1e5) t = '₹' + Math.round(price / 1e5) + 'L';
        else t = '₹' + price.toLocaleString('en-IN');
        return t;
      }

      function icon(m, selected) {
        return L.divIcon({
          className: '',
          html: '<div class="price-pill' + (selected ? ' selected' : '') + '">' + pill(m.price) + '</div>',
          iconSize: null
        });
      }

      function popupHtml(m) {
        return '<div class="popup-title">' + escapeHtml(m.title) + '</div>' +
               '<div class="popup-loc">' + escapeHtml(m.locationLabel) + '</div>' +
               '<div style="font-weight:700;margin-bottom:8px">' + pill(m.price) + (m.intent === 'rent' ? ' /mo' : '') + '</div>' +
               '<a class="popup-btn" href="#" onclick="window.__viewDetails(\\'' + m.id + '\\');return false;">View details</a>';
      }

      function escapeHtml(s) {
        return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
          return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
        });
      }

      window.__viewDetails = function (id) { post({ type: 'viewDetails', id: id }); };

      function render(markers) {
        markerLayer.clearLayers();
        byId = {};
        markers.forEach(function (m) {
          if (typeof m.lat !== 'number' || typeof m.lng !== 'number') return;
          var mk = L.marker([m.lat, m.lng], { icon: icon(m, m.id === selectedId) });
          mk.on('click', function () {
            selectedId = m.id;
            refreshIcons(markers);
            mk.bindPopup(popupHtml(m), { closeButton: true }).openPopup();
            post({ type: 'markerPress', id: m.id });
          });
          mk.addTo(markerLayer);
          byId[m.id] = { marker: mk, data: m };
        });
        window.__markers = markers;
      }

      function refreshIcons(markers) {
        markers.forEach(function (m) {
          var e = byId[m.id];
          if (e) e.marker.setIcon(icon(m, m.id === selectedId));
        });
      }

      function fitBounds() {
        var ms = window.__markers || [];
        var pts = ms.filter(function (m) { return typeof m.lat === 'number' && typeof m.lng === 'number'; })
                    .map(function (m) { return [m.lat, m.lng]; });
        if (pts.length === 1) { map.setView(pts[0], BOOT.mode === 'detail' ? 15 : 14); return; }
        if (pts.length > 1) { map.fitBounds(pts, { padding: [50, 50], maxZoom: 14 }); }
      }

      // One place that draws the pin, used by the tap handler and by the
      // setPin message, so a pin placed by the map and a pin placed by the
      // host cannot end up looking like two different things.
      function placePin(latlng) {
        if (pinMarker) map.removeLayer(pinMarker);
        pinMarker = L.circleMarker(latlng, {
          radius: 8, weight: 3, color: '#ffffff',
          fillColor: BOOT.brand, fillOpacity: 1
        }).addTo(map);
      }

      map.on('click', function (e) {
        if (pinDrop) placePin(e.latlng);
        post({ type: 'mapPress', lat: e.latlng.lat, lng: e.latlng.lng });
      });

      function handle(msg) {
        switch (msg.type) {
          case 'setMarkers': render(msg.markers || []); break;
          case 'setCenter': map.setView([msg.lat, msg.lng], msg.zoom || map.getZoom()); break;
          case 'setSelected':
            selectedId = msg.id;
            refreshIcons(window.__markers || []);
            var e = byId[msg.id];
            if (e) { map.setView([e.data.lat, e.data.lng], Math.max(map.getZoom(), 14)); e.marker.bindPopup(popupHtml(e.data)).openPopup(); }
            break;
          case 'fitBounds': fitBounds(); break;
          case 'setPin':
            // Centres as well as marks: the host sets a pin when it has learned
            // a coordinate from somewhere else (the device, a geocode), and a
            // pin outside the viewport communicates nothing.
            placePin(L.latLng(msg.lat, msg.lng));
            map.setView([msg.lat, msg.lng], Math.max(map.getZoom(), 15));
            break;
          case 'setPinDrop': pinDrop = !!msg.enabled; if (!pinDrop && pinMarker) { map.removeLayer(pinMarker); pinMarker = null; if (radiusCircle) { map.removeLayer(radiusCircle); radiusCircle = null; } } break;
          case 'setRadius':
            if (pinMarker) {
              if (radiusCircle) map.removeLayer(radiusCircle);
              radiusCircle = L.circle(pinMarker.getLatLng(), { radius: msg.km * 1000, color: '#22c55e', weight: 2, fillColor: '#22c55e', fillOpacity: 0.1 }).addTo(map);
            }
            break;
        }
      }

      // Both channels: Android delivers to document, iOS to window.
      document.addEventListener('message', function (e) { try { handle(JSON.parse(e.data)); } catch (x) {} });
      window.addEventListener('message', function (e) { try { handle(JSON.parse(e.data)); } catch (x) {} });

      post({ type: 'ready' });
    })();
  </script>
</body>
</html>`;
}
