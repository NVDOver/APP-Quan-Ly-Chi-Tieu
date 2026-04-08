"use client";

import { useState } from "react";
import dynamic from "next/dynamic";
import { MapPin, Target, ChevronUp } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover";

// Load MapPicker dynamically to avoid SSR errors with Leaflet
const MapPicker = dynamic(() => import("./map-picker"), { 
  ssr: false,
  loading: () => <div className="h-[300px] w-full bg-muted animate-pulse flex items-center justify-center text-xs text-muted-foreground">Đang tải bản đồ...</div>
});

interface LocationInputProps {
  onLocationChange: (data: { name: string; lat?: number; lng?: number }) => void;
  initialValue?: string;
  initialLat?: number;
  initialLng?: number;
}

export function LocationInput({ onLocationChange, initialValue = "", initialLat, initialLng }: LocationInputProps) {
  const [locationName, setLocationName] = useState(initialValue);
  const [lat, setLat] = useState<number | undefined>(initialLat);
  const [lng, setLng] = useState<number | undefined>(initialLng);
  const [isOpen, setIsOpen] = useState(false);

  const handleMapSelect = (newLat: number, newLng: number, address: string) => {
    setLat(newLat);
    setLng(newLng);
    // Only update name if it's currently empty
    if (!locationName) {
      setLocationName(address);
    }
    onLocationChange({ name: locationName || address, lat: newLat, lng: newLng });
  };

  const getUserLocation = () => {
    if ("geolocation" in navigator) {
      navigator.geolocation.getCurrentPosition((position) => {
        const newLat = position.coords.latitude;
        const newLng = position.coords.longitude;
        setLat(newLat);
        setLng(newLng);
        onLocationChange({ name: locationName, lat: newLat, lng: newLng });
      });
    }
  };

  return (
    <div className="space-y-2">
      <Label className="text-xs font-medium">Vị trí</Label>
      <div className="flex gap-2">
        <div className="relative flex-1">
          <Input 
            placeholder="Tên địa điểm, quán ăn..." 
            value={locationName}
            onChange={(e) => {
              setLocationName(e.target.value);
              onLocationChange({ name: e.target.value, lat, lng });
            }}
            className="pr-8"
          />
          <MapPin className="absolute right-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
        </div>
        
        <Popover open={isOpen} onOpenChange={setIsOpen}>
          <PopoverTrigger asChild>
            <Button variant="outline" size="icon" className="shrink-0">
               {isOpen ? <ChevronUp className="h-4 w-4" /> : <MapPin className="h-4 w-4" />}
            </Button>
          </PopoverTrigger>
          <PopoverContent className="w-[350px] p-0" align="end">
            <div className="p-4 space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-sm font-semibold">Chọn vị trí trên bản đồ</span>
                <Button variant="ghost" size="sm" className="h-8 px-2 text-xs" onClick={getUserLocation}>
                  <Target className="mr-1 h-3 w-3" />
                  Hiện tại
                </Button>
              </div>
              <MapPicker 
                initialCenter={lat && lng ? [lat, lng] : undefined} 
                onLocationSelect={handleMapSelect} 
              />
              {lat && lng && (
                <div className="text-[10px] text-muted-foreground bg-muted p-1.5 rounded flex justify-between">
                  <span>Lat: {lat.toFixed(4)}</span>
                  <span>Lng: {lng.toFixed(4)}</span>
                </div>
              )}
            </div>
          </PopoverContent>
        </Popover>
      </div>
    </div>
  );
}
