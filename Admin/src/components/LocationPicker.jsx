import React, { useState, useEffect, useRef, useMemo } from "react";
import { MapContainer, TileLayer, Marker, useMapEvents, useMap } from "react-leaflet";
import L from "leaflet";
import "leaflet/dist/leaflet.css";
import axios from "axios";
import { MapPin, Crosshair, ExternalLink, X, Loader2 } from "lucide-react";
import LocationAutocomplete from "./LocationAutocomplete";
import indiaStates from "../data/india-states.json";

// Fix for default marker icon in react-leaflet under Vite
delete L.Icon.Default.prototype._getIconUrl;
L.Icon.Default.mergeOptions({
  iconRetinaUrl: "https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/images/marker-icon-2x.png",
  iconUrl: "https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/images/marker-icon.png",
  shadowUrl: "https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/images/marker-shadow.png",
});

const customIcon = new L.Icon({
  iconUrl: "https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/images/marker-icon.png",
  iconRetinaUrl: "https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/images/marker-icon-2x.png",
  shadowUrl: "https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/images/marker-shadow.png",
  iconSize: [25, 41],
  iconAnchor: [12, 41],
  popupAnchor: [1, -34],
  shadowSize: [41, 41],
});

// Map click handler — drops a pin and updates parent via callback
function LocationMarker({ position, onPick }) {
  useMapEvents({
    click(e) {
      const { lat, lng } = e.latlng;
      onPick(lat, lng);
    },
  });
  return position ? <Marker position={position} icon={customIcon} /> : null;
}

// Recenter map when position changes
function RecenterMap({ position, zoom = 15 }) {
  const map = useMap();
  useEffect(() => {
    if (position && Array.isArray(position) && position.length === 2) {
      map.setView(position, zoom);
    }
  }, [position, map, zoom]);
  // Force Leaflet to recompute its size after the modal mounts.
  // Without this, the map renders blank inside a freshly-mounted flex parent.
  useEffect(() => {
    const t = setTimeout(() => map.invalidateSize(), 150);
    return () => clearTimeout(t);
  }, [map]);
  return null;
}

const DEFAULT_CENTER = [20.5937, 78.9629]; // India centroid

const inp = "w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500";
const lbl = "block text-sm font-medium text-gray-700 mb-1";

/**
 * Reusable location picker for the CreateProject wizard.
 *
 * Props:
 *   value     — { state, city, locality, microMarket, addressLine, landmark, pincode, lat, lng, distanceTo* }
 *   onChange(patch) — partial updates
 */
export default function LocationPicker({ value, onChange, errors = {} }) {
  const v = value || {};
  const set = (patch) => onChange(patch);

  // ── Map modal state ──
  const [mapOpen, setMapOpen] = useState(false);
  const [mapPosition, setMapPosition] = useState(null);
  const [locating, setLocating] = useState(false);
  const [reverseBusy, setReverseBusy] = useState(false);
  const [forwardBusy, setForwardBusy] = useState(false);
  const [cityGeoError, setCityGeoError] = useState("");

  // Keep map in sync with current lat/lng
  useEffect(() => {
    const lat = parseFloat(v.lat);
    const lng = parseFloat(v.lng);
    if (Number.isFinite(lat) && Number.isFinite(lng)) {
      setMapPosition([lat, lng]);
    } else {
      setMapPosition(null);
    }
  }, [v.lat, v.lng]);

  // ── State suggestions ──
  const stateSuggestions = useMemo(() => {
    const q = (v.state || "").trim().toLowerCase();
    return indiaStates.states
      .filter((s) => !q || s.name.toLowerCase().includes(q))
      .slice(0, 15)
      .map((s) => ({
        key: `state-${s.code}`,
        label: s.name,
        secondary: s.code,
        raw: s,
      }));
  }, [v.state]);

  // ── City suggestions (filtered by state) ──
  const citySuggestions = useMemo(() => {
    const q = (v.city || "").trim().toLowerCase();
    const stateObj = indiaStates.states.find(
      (s) => s.name.toLowerCase() === (v.state || "").trim().toLowerCase()
    );
    if (!stateObj) return [];
    return stateObj.cities
      .filter((c) => !q || c.name.toLowerCase().includes(q))
      .slice(0, 15)
      .map((c) => ({
        key: `city-${stateObj.code}-${c.name}`,
        label: c.name,
        secondary: stateObj.name,
        raw: { ...c, state: stateObj.name, stateCode: stateObj.code },
      }));
  }, [v.state, v.city]);

  // ── Nominatim forward geocode fallback for unknown cities ──
  const cityGeoTimeoutRef = useRef(null);
  useEffect(() => {
    setCityGeoError("");
    if (!v.city || v.city.trim().length < 3) return;

    // Skip if the city exactly matches one in our local JSON
    const stateObj = indiaStates.states.find(
      (s) => s.name.toLowerCase() === (v.state || "").trim().toLowerCase()
    );
    const exactMatch =
      stateObj && stateObj.cities.find((c) => c.name.toLowerCase() === v.city.trim().toLowerCase());
    if (exactMatch) return;

    if (cityGeoTimeoutRef.current) clearTimeout(cityGeoTimeoutRef.current);
    cityGeoTimeoutRef.current = setTimeout(async () => {
      setForwardBusy(true);
      try {
        const q = `${v.city}${v.state ? ", " + v.state : ""}, India`;
        const res = await axios.get("https://nominatim.openstreetmap.org/search", {
          params: { format: "json", q, addressdetails: 1, limit: 1 },
          headers: { "Accept-Language": "en" },
        });
        const best = res.data?.[0];
        if (!best) {
          setCityGeoError("Could not locate that city — please pick on the map.");
          return;
        }
        const lat = parseFloat(best.lat);
        const lon = parseFloat(best.lon);
        if (!Number.isFinite(lat) || !Number.isFinite(lon)) return;
        // Only auto-fill if user hasn't manually set coords (or they match the city)
        const addr = best.address || {};
        const patch = {
          lat: lat.toFixed(6),
          lng: lon.toFixed(6),
        };
        if (addr.state && !v.state) patch.state = addr.state;
        if (addr.postcode && !v.pincode) patch.pincode = addr.postcode;
        set(patch);
        setMapPosition([lat, lon]);
      } catch (e) {
        // Silent — user can still use the map
      } finally {
        setForwardBusy(false);
      }
    }, 800);

    return () => {
      if (cityGeoTimeoutRef.current) clearTimeout(cityGeoTimeoutRef.current);
    };
  }, [v.city, v.state]);

  // ── State select ──
  const handleStateSelect = (item) => {
    set({
      state: item.raw.name,
      city: "",
      lat: item.raw.lat ? item.raw.lat.toFixed(6) : v.lat,
      lng: item.raw.lon ? item.raw.lon.toFixed(6) : v.lng,
    });
    setMapPosition([item.raw.lat, item.raw.lon]);
  };

  // ── City select ──
  const handleCitySelect = (item) => {
    set({
      city: item.raw.name,
      lat: item.raw.lat.toFixed(6),
      lng: item.raw.lon.toFixed(6),
    });
    setMapPosition([item.raw.lat, item.raw.lon]);
  };

  // ── Nominatim reverse geocode (for map picker) ──
  const reverseGeocode = async (lat, lng) => {
    setReverseBusy(true);
    try {
      const res = await axios.get(
        `https://nominatim.openstreetmap.org/reverse?format=json&lat=${lat}&lon=${lng}&addressdetails=1&zoom=18`,
        { headers: { "Accept-Language": "en" } }
      );
      if (res.data?.address) {
        const a = res.data.address;
        const city = a.city || a.town || a.village || a.state_district || a.county || "";
        const locality =
          a.suburb || a.neighbourhood || a.hamlet || a.residential || a.quarter || "";
        const landmark = a.amenity || a.building || a.shop || a.tourism || a.leisure || "";
        const state = a.state || "";
        const pincode = a.postcode || "";

        const patch = {};
        if (state) patch.state = state;
        if (city) patch.city = city;
        if (locality) patch.locality = locality;
        if (landmark) patch.landmark = landmark;
        if (pincode) patch.pincode = pincode;
        set(patch);
      }
    } catch (e) {
      // Silent
    } finally {
      setReverseBusy(false);
    }
  };

  // ── Map click: drop pin, set lat/lng, reverse-geocode ──
  const handleMapPick = (lat, lng) => {
    setMapPosition([lat, lng]);
    set({ lat: lat.toFixed(6), lng: lng.toFixed(6) });
    reverseGeocode(lat, lng);
  };

  // ── Confirm map pick: close modal ──
  const confirmMap = () => {
    setMapOpen(false);
  };

  // ── "Use my location" ──
  const useMyLocation = () => {
    if (!navigator.geolocation) {
      alert("Geolocation is not supported by your browser.");
      return;
    }
    setLocating(true);
    navigator.geolocation.getCurrentPosition(
      (pos) => {
        const { latitude, longitude } = pos.coords;
        setMapPosition([latitude, longitude]);
        set({ lat: latitude.toFixed(6), lng: longitude.toFixed(6) });
        setLocating(false);
        reverseGeocode(latitude, longitude);
      },
      (err) => {
        setLocating(false);
        const messages = {
          1: "Location permission denied. Please enable it in your browser settings.",
          2: "Location unavailable. Please check your GPS/network settings.",
          3: "Location request timed out. Please try again or enter manually.",
        };
        alert(messages[err.code] || "Could not get your location. Please enter it manually.");
      },
      { enableHighAccuracy: true, timeout: 15000, maximumAge: 0 }
    );
  };

  const hasCoords =
    v.lat !== "" && v.lng !== "" &&
    v.lat !== null && v.lng !== null &&
    v.lat !== undefined && v.lng !== undefined;

  return (
    <div className="space-y-4">
      <h2 className="text-lg font-semibold text-gray-800">Location Details</h2>

      <div className="grid grid-cols-2 gap-4">
        <div>
          <label className={lbl}>State *</label>
          <div data-field="state">
            <LocationAutocomplete
              value={v.state || ""}
              onChange={(text) => set({ state: text })}
              onSelect={handleStateSelect}
              suggestions={stateSuggestions}
              placeholder="Search state..."
              required
              icon={<MapPin size={16} />}
              error={errors.state}
            />
          </div>
        </div>
        <div>
          <label className={lbl}>City *</label>
          <div data-field="city">
            <LocationAutocomplete
              value={v.city || ""}
              onChange={(text) => set({ city: text })}
              onSelect={handleCitySelect}
              suggestions={citySuggestions}
              placeholder={
                v.state ? "Search city..." : "Select a state first"
              }
              required
              disabled={!v.state && citySuggestions.length === 0}
              icon={<MapPin size={16} />}
              error={errors.city || cityGeoError}
            />
          </div>
          {forwardBusy && (
            <p className="text-xs text-gray-500 mt-1 flex items-center gap-1">
              <Loader2 size={12} className="animate-spin" /> Locating on map…
            </p>
          )}
        </div>
        <div>
          <label className={lbl}>Locality *</label>
          <input
            data-field="locality"
            className={errors.locality ? "w-full border border-red-400 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-red-300" : inp}
            value={v.locality || ""}
            onChange={(e) => set({ locality: e.target.value })}
            placeholder="e.g. Whitefield"
          />
          {errors.locality && <p className="text-xs text-red-500 mt-1">{errors.locality}</p>}
        </div>
        <div>
          <label className={lbl}>Micro Market</label>
          <input
            data-field="microMarket"
            className={inp}
            value={v.microMarket || ""}
            onChange={(e) => set({ microMarket: e.target.value })}
            placeholder="e.g. East Bangalore"
          />
        </div>
        <div>
          <label className={lbl}>Address Line</label>
          <input
            data-field="addressLine"
            className={inp}
            value={v.addressLine || ""}
            onChange={(e) => set({ addressLine: e.target.value })}
            placeholder="Street, building, etc."
          />
        </div>
        <div>
          <label className={lbl}>Landmark</label>
          <input
            data-field="landmark"
            className={inp}
            value={v.landmark || ""}
            onChange={(e) => set({ landmark: e.target.value })}
            placeholder="e.g. Near Phoenix Mall"
          />
        </div>
        <div>
          <label className={lbl}>Pincode *</label>
          <input
            data-field="pincode"
            className={errors.pincode ? "w-full border border-red-400 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-red-300" : inp}
            value={v.pincode || ""}
            onChange={(e) => set({ pincode: e.target.value })}
            placeholder="e.g. 560066"
          />
          {errors.pincode && <p className="text-xs text-red-500 mt-1">{errors.pincode}</p>}
        </div>
      </div>

      {/* ── Coordinates & map actions ── */}
      <div className="border-t border-gray-200 pt-4 mt-2">
        <div className="grid grid-cols-2 gap-4">
          <div>
            <label className={lbl}>Latitude *</label>
            <input
              data-field="coords"
              className={errors.coords ? "w-full border border-red-400 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-red-300" : inp}
              type="number"
              step="any"
              value={v.lat || ""}
              onChange={(e) => set({ lat: e.target.value })}
              placeholder="e.g. 12.9716"
            />
          </div>
          <div>
            <label className={lbl}>Longitude *</label>
            <input
              data-field="coords"
              className={errors.coords ? "w-full border border-red-400 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-red-300" : inp}
              type="number"
              step="any"
              value={v.lng || ""}
              onChange={(e) => set({ lng: e.target.value })}
              placeholder="e.g. 77.5946"
            />
          </div>
        </div>
        {errors.coords && <p className="text-xs text-red-500 mt-1">{errors.coords}</p>}

        <div className="flex flex-wrap items-center gap-2 mt-3">
          <button
            type="button"
            onClick={() => setMapOpen(true)}
            className="inline-flex items-center gap-1.5 px-3 py-2 bg-blue-600 text-white rounded-lg text-sm hover:bg-blue-700"
          >
            <MapPin size={16} /> Pick on Map
          </button>
          <button
            type="button"
            onClick={useMyLocation}
            disabled={locating}
            className="inline-flex items-center gap-1.5 px-3 py-2 border border-gray-300 rounded-lg text-sm text-gray-700 hover:bg-gray-50 disabled:opacity-50"
          >
            {locating ? <Loader2 size={16} className="animate-spin" /> : <Crosshair size={16} />}
            Use My Location
          </button>
          {hasCoords && (
            <a
              href={`https://www.google.com/maps/search/?api=1&query=${v.lat},${v.lng}`}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1.5 px-3 py-2 text-sm text-blue-600 hover:underline"
            >
              Open in Google Maps <ExternalLink size={14} />
            </a>
          )}
        </div>
      </div>

      {/* ── Connectivity ── */}
      <h3 className="font-medium text-gray-700 pt-2">Connectivity</h3>
      <div className="grid grid-cols-2 gap-4">
        <div>
          <label className={lbl}>Distance to Metro</label>
          <input
            className={inp}
            value={v.distanceToMetro || ""}
            onChange={(e) => set({ distanceToMetro: e.target.value })}
            placeholder="e.g. 1.2 km"
          />
        </div>
        <div>
          <label className={lbl}>Distance to Airport</label>
          <input
            className={inp}
            value={v.distanceToAirport || ""}
            onChange={(e) => set({ distanceToAirport: e.target.value })}
            placeholder="e.g. 18 km"
          />
        </div>
        <div>
          <label className={lbl}>Distance to Railway</label>
          <input
            className={inp}
            value={v.distanceToRailway || ""}
            onChange={(e) => set({ distanceToRailway: e.target.value })}
            placeholder="e.g. 4 km"
          />
        </div>
        <div>
          <label className={lbl}>Distance to Bus Stop</label>
          <input
            className={inp}
            value={v.distanceToBusStop || ""}
            onChange={(e) => set({ distanceToBusStop: e.target.value })}
            placeholder="e.g. 500 m"
          />
        </div>
      </div>

      {/* ── Map modal ── */}
      {mapOpen && (
        <div
          className="fixed inset-0 z-[9999] flex items-center justify-center bg-black/50 p-4"
          onClick={(e) => {
            if (e.target === e.currentTarget) setMapOpen(false);
          }}
        >
          <div className="bg-white rounded-2xl shadow-2xl w-full max-w-3xl max-h-[80vh] flex flex-col overflow-hidden">
            <div className="flex items-center justify-between px-5 py-3 border-b border-gray-200">
              <h3 className="font-semibold text-gray-800 flex items-center gap-2">
                <MapPin size={18} className="text-blue-600" />
                Pick Location on Map
                {reverseBusy && <Loader2 size={14} className="animate-spin text-gray-400" />}
              </h3>
              <button
                type="button"
                onClick={() => setMapOpen(false)}
                className="text-gray-400 hover:text-gray-600"
                aria-label="Close"
              >
                <X size={20} />
              </button>
            </div>
            <div className="h-[60vh] min-h-[400px] w-full">
              <MapContainer
                center={mapPosition || DEFAULT_CENTER}
                zoom={mapPosition ? 15 : 5}
                style={{ height: "100%", width: "100%" }}
                scrollWheelZoom
              >
                <TileLayer
                  attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a>'
                  url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
                />
                <LocationMarker position={mapPosition} onPick={handleMapPick} />
                <RecenterMap position={mapPosition} zoom={15} />
              </MapContainer>
            </div>
            <div className="px-5 py-3 border-t border-gray-200 flex items-center justify-between gap-3">
              <p className="text-xs text-gray-500">
                Click anywhere on the map to drop a pin. State, city, locality and pincode will auto-fill.
              </p>
              <div className="flex gap-2">
                <button
                  type="button"
                  onClick={() => setMapOpen(false)}
                  className="px-4 py-2 border border-gray-300 rounded-lg text-sm text-gray-700 hover:bg-gray-50"
                >
                  Cancel
                </button>
                <button
                  type="button"
                  onClick={confirmMap}
                  className="px-4 py-2 bg-blue-600 text-white rounded-lg text-sm hover:bg-blue-700"
                >
                  Confirm
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
