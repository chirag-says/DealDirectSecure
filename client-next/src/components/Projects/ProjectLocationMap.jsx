'use client';

/**
 * The project location map.
 *
 * Every one of the seven live projects has coordinates stored, and until now
 * none of them reached a buyer: the project page had no map at all, despite
 * react-leaflet shipping in the bundle and the Admin wizard having a
 * drag-to-place LocationPicker. Admins were filling a field into a void.
 *
 * MUST be dynamically imported with `ssr: false` by the parent. Leaflet reads
 * `window` at module scope, so server-rendering it does not degrade the map —
 * it throws and takes the whole page with it.
 *
 * Connectivity distances render beneath it because they answer the question the
 * map raises ("where is this, and what is it near?") and because they are
 * likewise collected and likewise unrendered — 5 of 7 projects have them.
 */

import React from 'react';
import { MapContainer, TileLayer, Marker, Popup } from 'react-leaflet';
import L from 'leaflet';
import 'leaflet/dist/leaflet.css';
import { Train, Plane, TrainFront, Bus, MapPin } from 'lucide-react';

// Leaflet's default marker resolves its images relative to the CSS file, which
// bundlers rewrite — the icons 404 and markers render blank. Pointing them at
// the CDN is the same fix PropertyListContent already uses; keeping both on the
// same source avoids two different broken-marker bugs later.
delete L.Icon.Default.prototype._getIconUrl;
L.Icon.Default.mergeOptions({
  iconRetinaUrl: 'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/images/marker-icon-2x.png',
  iconUrl: 'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/images/marker-icon.png',
  shadowUrl: 'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/images/marker-shadow.png',
});

/**
 * Distances are stored as free text ("1.2 km", "20 mins"). TNRERA's 2025 rules
 * require distance, not travel time, so anything time-shaped is shown as
 * entered rather than dressed up as a distance — the honest render of a value
 * we cannot convert.
 */
const CONNECTIONS = [
  ['distanceToMetro', 'Metro', Train],
  ['distanceToRailway', 'Railway', TrainFront],
  ['distanceToAirport', 'Airport', Plane],
  ['distanceToBusStop', 'Bus stop', Bus],
];

export default function ProjectLocationMap({ project }) {
  const lat = project?.location?.coordinates?.lat;
  const lng = project?.location?.coordinates?.lng;
  const hasPin = Number.isFinite(lat) && Number.isFinite(lng);

  const connectivity = project?.location?.connectivity || {};
  const links = CONNECTIONS
    .map(([key, label, Icon]) => [key, label, Icon, connectivity[key]])
    .filter(([, , , value]) => Boolean(value));

  // Nothing to show at all — render nothing rather than an empty framed box.
  if (!hasPin && links.length === 0) return null;

  const place = [
    project?.location?.locality,
    project?.location?.city,
  ].filter(Boolean).join(', ');

  return (
    <div className="bg-white rounded-2xl border border-slate-200 p-5">
      <h2 className="font-bold text-slate-900 mb-4 flex items-center gap-2">
        <MapPin size={16} /> Location
      </h2>

      {hasPin && (
        <div className="h-72 rounded-xl overflow-hidden border border-slate-100">
          <MapContainer
            center={[lat, lng]}
            zoom={15}
            scrollWheelZoom={false}
            style={{ height: '100%', width: '100%' }}
          >
            <TileLayer
              attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a>'
              url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
            />
            <Marker position={[lat, lng]}>
              <Popup>
                <span className="font-semibold">{project?.basics?.name}</span>
                {place && <><br />{place}</>}
              </Popup>
            </Marker>
          </MapContainer>
        </div>
      )}

      {project?.location?.addressLine && (
        <p className="text-sm text-slate-600 mt-3">
          {project.location.addressLine}
          {project.location.landmark ? ` · Near ${project.location.landmark}` : ''}
          {project.location.pincode ? ` · ${project.location.pincode}` : ''}
        </p>
      )}

      {links.length > 0 && (
        <div className="mt-4">
          <p className="text-xs font-semibold text-slate-400 uppercase tracking-wide mb-2">
            Connectivity
          </p>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
            {links.map(([key, label, Icon, value]) => (
              <div key={key} className="bg-slate-50 rounded-xl px-3 py-2.5">
                <div className="flex items-center gap-1.5 text-slate-400 mb-0.5">
                  <Icon size={12} />
                  <span className="text-[11px]">{label}</span>
                </div>
                <p className="text-sm font-semibold text-slate-800">{value}</p>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
