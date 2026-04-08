"use client";

import { useState, useEffect } from "react";
import dynamic from "next/dynamic";
import { MapPin, Navigation } from "lucide-react";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { formatCurrency } from "@/lib/utils";

// Load actual Leaflet parts dynamically
const MapContainer = dynamic(() => import("react-leaflet").then(mod => mod.MapContainer), { ssr: false });
const TileLayer = dynamic(() => import("react-leaflet").then(mod => mod.TileLayer), { ssr: false });
const Marker = dynamic(() => import("react-leaflet").then(mod => mod.Marker), { ssr: false });
const Popup = dynamic(() => import("react-leaflet").then(mod => mod.Popup), { ssr: false });

export interface MapTransaction {
  id: string;
  amount: number;
  type: string;
  locationName: string | null;
  latitude: number | null;
  longitude: number | null;
  category: { name: string } | null;
}

interface TransactionMapProps {
  transactions: MapTransaction[];
}

export function TransactionMap({ transactions }: TransactionMapProps) {
  const [isMounted, setIsMounted] = useState(false);

  useEffect(() => {
    setIsMounted(true);
    
    // Fix leaflet icon
    import("leaflet").then(L => {
      const DefaultIcon = L.default.icon({
        iconUrl: "https://unpkg.com/leaflet@1.9.4/dist/images/marker-icon.png",
        shadowUrl: "https://unpkg.com/leaflet@1.9.4/dist/images/marker-shadow.png",
        iconSize: [25, 41],
        iconAnchor: [12, 41],
      });
      L.default.Marker.prototype.options.icon = DefaultIcon;
    });
  }, []);

  if (!isMounted || transactions.length === 0) {
    return (
      <Card className="h-full min-h-[400px] flex items-center justify-center border-none shadow-sm">
        <div className="text-center space-y-2">
          <Navigation className="h-10 w-10 text-muted-foreground/20 mx-auto" />
          <p className="text-sm text-muted-foreground">Chưa có giao dịch nào có vị trí hiển thị</p>
        </div>
      </Card>
    );
  }

  // Calculate center based on markers
  const validCoords = transactions.filter(t => t.latitude && t.longitude);
  const center: [number, number] = validCoords.length > 0 
    ? [validCoords[0].latitude!, validCoords[0].longitude!]
    : [21.0285, 105.8542];

  return (
    <Card className="h-full min-h-[400px] overflow-hidden border-none shadow-sm group">
      <CardHeader className="pb-3">
        <CardTitle className="text-lg flex items-center gap-2">
          <MapPin className="h-5 w-5 text-rose-500" />
          Bản đồ Chi tiêu
        </CardTitle>
      </CardHeader>
      <CardContent className="p-0 h-[320px]">
        <MapContainer 
          center={center} 
          zoom={12} 
          style={{ height: "100%", width: "100%" }}
          scrollWheelZoom={false}
        >
          <TileLayer
            attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors'
            url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
          />
          {validCoords.map((t) => (
            <Marker key={t.id} position={[t.latitude!, t.longitude!]}>
              <Popup>
                <div className="p-1">
                  <p className="font-bold text-sm border-b pb-1 mb-1">{t.category?.name || "Giao dịch"}</p>
                  <p className={`text-xs font-semibold ${t.type === 'EXPENSE' ? 'text-red-500' : 'text-emerald-500'}`}>
                    {t.type === 'EXPENSE' ? '-' : '+'}{formatCurrency(Number(t.amount))}
                  </p>
                  <p className="text-[10px] text-muted-foreground mt-1 italic">{t.locationName}</p>
                </div>
              </Popup>
            </Marker>
          ))}
        </MapContainer>
      </CardContent>
    </Card>
  );
}
