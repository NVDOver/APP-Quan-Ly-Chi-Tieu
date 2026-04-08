"use client";

import { useState, useEffect } from "react";
import { MapContainer, TileLayer, Marker, useMapEvents, useMap } from "react-leaflet";
import L from "leaflet";
import "leaflet/dist/leaflet.css";

// Fix Leaflet default icon issue
const DefaultIcon = L.icon({
  iconUrl: "https://unpkg.com/leaflet@1.9.4/dist/images/marker-icon.png",
  shadowUrl: "https://unpkg.com/leaflet@1.9.4/dist/images/marker-shadow.png",
  iconSize: [25, 41],
  iconAnchor: [12, 41],
});

L.Marker.prototype.options.icon = DefaultIcon;

interface MapPickerProps {
  initialCenter?: [number, number];
  onLocationSelect: (lat: number, lng: number, address: string) => void;
}

function LocationMarker({ 
  position, 
  setPosition 
}: { 
  position: [number, number] | null, 
  setPosition: (pos: [number, number]) => void 
}) {
  const map = useMap();

  useMapEvents({
    click(e) {
      setPosition([e.latlng.lat, e.latlng.lng]);
    },
  });

  useEffect(() => {
    if (position) {
      map.flyTo(position, map.getZoom());
    }
  }, [position, map]);

  return position === null ? null : (
    <Marker position={position} />
  );
}

export default function MapPicker({ initialCenter = [21.0285, 105.8542], onLocationSelect }: MapPickerProps) {
  const [position, setPosition] = useState<[number, number] | null>(null);
  const [isSearching, setIsSearching] = useState(false);

  const handleSelect = async (pos: [number, number]) => {
    setPosition(pos);
    setIsSearching(true);
    try {
      // Reverse Geocoding using Nominatim
      const response = await fetch(
        `https://nominatim.openstreetmap.org/reverse?format=jsonv2&lat=${pos[0]}&lon=${pos[1]}`
      );
      const data = await response.json();
      const address = data.display_name || "Vị trí đã chọn";
      onLocationSelect(pos[0], pos[1], address);
    } catch (error) {
      console.error("Geocoding error:", error);
      onLocationSelect(pos[0], pos[1], "Vị trí không xác định");
    } finally {
      setIsSearching(false);
    }
  };

  return (
    <div className="h-[300px] w-full rounded-md border overflow-hidden relative">
      <MapContainer 
        center={initialCenter} 
        zoom={13} 
        style={{ height: "100%", width: "100%" }}
      >
        <TileLayer
          attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors'
          url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
        />
        <LocationMarker position={position} setPosition={handleSelect} />
      </MapContainer>
      {isSearching && (
        <div className="absolute inset-0 bg-background/50 flex items-center justify-center z-[1000]">
          <span className="text-sm font-medium animate-pulse">Đang xác định địa chỉ...</span>
        </div>
      )}
      <div className="absolute bottom-2 left-2 z-[1000] bg-background/80 p-1 rounded text-[10px] text-muted-foreground border">
        Click để chọn vị trí
      </div>
    </div>
  );
}
