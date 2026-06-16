'use client';

import React from "react";
import { useRouter } from "next/navigation";
import { MapPin } from "lucide-react";

// Import top locality images
import bangaloretop from "../../assets/bangaloretop.jpg";
import bihartop from "../../assets/bihartop.jpg";
import delhitop from "../../assets/delhitop.jpg";
import gujarattop from "../../assets/gujarattop.jpg";
import gurgaontop from "../../assets/gurgaontop.jpg";
import hyderabadtop from "../../assets/Hyderabadtop.jpg";
import kolkatatop from "../../assets/kolkatatop.jpg";
import mumbaitop from "../../assets/mumbaitop.jpg";

// --- Internal LogoLoop Component ---
const LogoLoop = ({ logos, speed = 50, direction = "left", gap = 24 }) => {
  // Duplicate logos to create seamless loop
  const scrollerContent = [...logos, ...logos];

  return (
    <div className="w-full overflow-hidden relative">
      <style>{`
        @keyframes scroll-left {
          0% { transform: translateX(0); }
          100% { transform: translateX(-50%); }
        }
        @keyframes scroll-right {
          0% { transform: translateX(-50%); }
          100% { transform: translateX(0); }
        }
        .animate-scroll-left {
          animation: scroll-left var(--speed) linear infinite;
        }
        .animate-scroll-right {
          animation: scroll-right var(--speed) linear infinite;
        }
        .pause-hover:hover {
          animation-play-state: paused;
        }
      `}</style>
      <div
        className={`flex w-max pause-hover ${direction === 'right' ? 'animate-scroll-right' : 'animate-scroll-left'}`}
        style={{
          '--speed': `${1000 / speed * 2}s`,
          gap: `${gap}px`
        }}
      >
        {scrollerContent.map((item, idx) => (
          <div key={`${idx}-${item.title}`} className="flex-shrink-0">
            {item.node}
          </div>
        ))}
      </div>
    </div>
  );
};

const TopLocalities = () => {
  const router = useRouter();

  const localities = [
    {
      id: 1,
      name: "Bangalore",
      city: "Bangalore",
      image: bangaloretop,
    },
    {
      id: 2,
      name: "Mumbai",
      city: "Mumbai",
      image: mumbaitop,
    },
    {
      id: 3,
      name: "Gurgaon",
      city: "Gurgaon",
      image: gurgaontop,
    },
    {
      id: 4,
      name: "Hyderabad",
      city: "Hyderabad",
      image: hyderabadtop,
    },
    {
      id: 5,
      name: "Kolkata",
      city: "Kolkata",
      image: kolkatatop,
    },
    {
      id: 6,
      name: "Delhi",
      city: "Delhi",
      image: delhitop,
    },
    {
      id: 7,
      name: "Ahmedabad",
      city: "Ahmedabad",
      image: gujarattop,
    },
    {
      id: 8,
      name: "Patna",
      city: "Patna",
      image: bihartop,
    },
  ];

  // Handler for locality click
  const handleLocalityClick = (city) => {
    router.push(`/properties?city=${encodeURIComponent(city)}`);
  };

  // Convert localities to logo format for LogoLoop
  const localityLogos = localities.map((locality) => ({
    node: (
      <div
        onClick={() => handleLocalityClick(locality.city)}
        className="flex flex-col items-center gap-3 px-5 py-4 bg-white rounded-xl shadow-sm hover:shadow-md transition-all border border-gray-100 cursor-pointer hover:border-blue-300"
      >
        <div className="w-24 h-24 rounded-lg overflow-hidden border-2 border-blue-100 relative flex-shrink-0">
          <img
            src={typeof locality.image === 'string' ? locality.image : locality.image.src}
            alt={locality.name}
            className="w-full h-full object-cover"
            onError={(e) => {
              e.target.parentElement.innerHTML = `<div class="w-full h-full bg-gradient-to-br from-blue-50 to-blue-100 flex items-center justify-center"><svg class="w-8 h-8 text-blue-500" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M5.05 4.05a7 7 0 119.9 9.9L10 18.9l-4.95-4.95a7 7 0 010-9.9zM10 11a2 2 0 100-4 2 2 0 000 4z" clip-rule="evenodd"></path></svg></div>`;
            }}
          />
        </div>

        <div className="text-center min-w-[160px]">
          <h3 className="text-sm font-bold text-gray-900 mb-1 line-clamp-1">
            {locality.name}
          </h3>
        </div>
      </div>
    ),
    title: locality.name,
  }));

  return (
    <section className="w-full py-12 bg-gradient-to-b from-gray-50 to-white">
      <div className="max-w-7xl mx-auto px-3 sm:px-6">
        {/* Header */}
        <div className="mb-8 text-center">
          <h2 className="text-2xl sm:text-3xl font-bold mb-3 text-gray-900">
            Top Localities in India
          </h2>
          <p className="text-gray-600 text-sm leading-relaxed max-w-4xl mx-auto">
            The right locality can make or break your home-buying experience. Our expert-picked top localities across India are renowned for their balanced development, lifestyle comfort, and strong return on investment. Whether you desire a serene hideaway or a vibrant city experience, choose a locality that grows with you.
          </p>
        </div>

        {/* LogoLoop Animation */}
        <div className="relative overflow-hidden py-4">
          <LogoLoop
            logos={localityLogos}
            speed={30}
            direction="left"
            logoHeight={16}
            gap={24}
          />
        </div>

        {/* View All Button */}
        <div className="mt-8 text-center">
          <button
            onClick={() => router.push('/properties')}
            className="inline-flex items-center gap-2 px-6 py-3 bg-blue-600 text-white font-semibold rounded-lg hover:bg-blue-700 transition-all shadow-md hover:shadow-lg text-sm"
          >
            <MapPin className="w-4 h-4" />
            <span>Explore All Localities in India</span>
          </button>
        </div>
      </div>
    </section>
  );
};

export default TopLocalities;