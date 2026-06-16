'use client';

import React from 'react';
import { 
  Paintbrush, 
  Landmark, 
  Truck, 
  Sparkles, 
  Wind, 
  Hammer, 
  Zap, 
  Droplet,
  ArrowRight,
  Sofa
} from 'lucide-react';
import Link from 'next/link';

export default function ComingSoonContent() {
  const upcomingFeatures = [
    {
      title: "Interior Design",
      description: "Transform your new house into a home with expert interior design, 3D visualization, and execution services.",
      icon: Sofa,
      color: "from-amber-400 to-orange-500",
      delay: "delay-[0ms]"
    },
    {
      title: "Apply Home Loan",
      description: "Get instant loan approvals and compare competitive interest rates directly from top partner banks.",
      icon: Landmark,
      color: "from-blue-500 to-indigo-600",
      delay: "delay-[100ms]"
    },
    {
      title: "Packers and Movers",
      description: "Stress-free relocation services with verified, professional packing and moving partners.",
      icon: Truck,
      color: "from-emerald-400 to-teal-600",
      delay: "delay-[200ms]"
    },
    {
      title: "Painting Services",
      description: "Give your walls a fresh look with professional home painting, waterproofing, and polishing.",
      icon: Paintbrush,
      color: "from-pink-500 to-rose-600",
      delay: "delay-[300ms]"
    },
    {
      title: "Deep Cleaning Services",
      description: "Specialized deep cleaning for sofas, bathrooms, kitchens, and full-house sanitization packages.",
      icon: Sparkles,
      color: "from-cyan-400 to-blue-500",
      delay: "delay-[400ms]"
    },
    {
      title: "AC Services",
      description: "Stay cool with expert air conditioning repair, regular maintenance, and installation services.",
      icon: Wind,
      color: "from-sky-300 to-blue-400",
      delay: "delay-[500ms]"
    },
    {
      title: "Carpentry Works",
      description: "Custom furniture crafting, repairs, and premium woodwork by skilled, verified carpenters.",
      icon: Hammer,
      color: "from-orange-700 to-amber-900",
      delay: "delay-[600ms]"
    },
    {
      title: "Electrician Services",
      description: "Safe and reliable electrical repairs, wiring, and appliance installation at your doorstep.",
      icon: Zap,
      color: "from-yellow-400 to-amber-500",
      delay: "delay-[700ms]"
    },
    {
      title: "Plumbing Services",
      description: "Quick fixes for leaks, pipe installations, and complete bathroom fittings by experts.",
      icon: Droplet,
      color: "from-blue-400 to-indigo-500",
      delay: "delay-[800ms]"
    }
  ];

  return (
    <div className="min-h-screen bg-slate-50 pt-24 pb-20 relative overflow-hidden font-sans">
      {/* Background Decorative Blobs */}
      <div className="absolute top-0 right-0 -translate-y-12 translate-x-1/3 w-96 h-96 bg-red-400/20 rounded-full blur-[100px] pointer-events-none"></div>
      <div className="absolute bottom-0 left-0 translate-y-1/3 -translate-x-1/3 w-[500px] h-[500px] bg-blue-400/20 rounded-full blur-[120px] pointer-events-none"></div>

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 relative z-10">
        
        {/* Header Section */}
        <div className="text-center max-w-3xl mx-auto mb-16 animate-in slide-in-from-bottom-8 fade-in duration-1000">
          <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-red-50 border border-red-100 text-red-600 text-sm font-bold mb-6">
            <Sparkles className="w-4 h-4" />
            <span>On the Horizon</span>
          </div>
          <h1 className="text-4xl md:text-6xl font-extrabold text-slate-900 mb-6 tracking-tight">
            We're building the future of <span className="text-transparent bg-clip-text bg-gradient-to-r from-red-600 to-orange-500">Property Services</span>
          </h1>
          <p className="text-lg md:text-xl text-slate-600 leading-relaxed">
            From finding your dream home to moving in and maintaining it, DealDirect is expanding to bring you a complete, end-to-end real estate experience. Here's a sneak peek at what's coming next.
          </p>
        </div>

        {/* Features Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 lg:gap-8">
          {upcomingFeatures.map((feature, idx) => {
            const Icon = feature.icon;
            return (
              <div 
                key={idx} 
                className={`group relative bg-white/60 backdrop-blur-xl border border-white/80 rounded-3xl p-8 shadow-sm hover:shadow-2xl hover:-translate-y-2 transition-all duration-500 overflow-hidden animate-in slide-in-from-bottom-12 fade-in fill-mode-both ${feature.delay}`}
              >
                {/* Glow effect on hover */}
                <div className="absolute inset-0 bg-gradient-to-br from-white/40 to-white/0 opacity-0 group-hover:opacity-100 transition-opacity duration-500"></div>
                
                <div className={`w-14 h-14 rounded-2xl flex items-center justify-center mb-6 bg-gradient-to-br ${feature.color} shadow-lg shadow-${feature.color.split('-')[1]}/30 text-white transform group-hover:scale-110 group-hover:rotate-3 transition-transform duration-500`}>
                  <Icon className="w-7 h-7" />
                </div>
                
                <h3 className="text-xl font-bold text-slate-900 mb-3 group-hover:text-red-600 transition-colors">
                  {feature.title}
                </h3>
                
                <p className="text-slate-600 leading-relaxed">
                  {feature.description}
                </p>

                <div className="mt-6 flex items-center text-sm font-semibold text-slate-400 uppercase tracking-wider gap-2">
                  <div className="w-2 h-2 rounded-full bg-amber-400 animate-pulse"></div>
                  In Development
                </div>
              </div>
            );
          })}
        </div>

        {/* Call to Action */}
        <div className="mt-20 text-center animate-in fade-in duration-1000 delay-[1000ms] fill-mode-both">
          <div className="bg-slate-900 rounded-3xl p-10 md:p-16 relative overflow-hidden shadow-2xl">
            {/* Background elements */}
            <div className="absolute top-0 right-0 w-64 h-64 bg-red-600/20 rounded-full blur-3xl"></div>
            <div className="absolute bottom-0 left-0 w-64 h-64 bg-blue-600/20 rounded-full blur-3xl"></div>
            
            <div className="relative z-10">
              <h2 className="text-3xl md:text-4xl font-extrabold text-white mb-4">Want to be the first to know?</h2>
              <p className="text-slate-300 text-lg mb-8 max-w-2xl mx-auto">
                We'll notify you as soon as these features launch. In the meantime, explore our massive inventory of verified properties.
              </p>
              <Link 
                href="/properties" 
                className="inline-flex items-center gap-2 bg-red-600 hover:bg-red-500 text-white font-bold text-lg px-8 py-4 rounded-xl shadow-lg shadow-red-600/30 hover:shadow-red-600/50 hover:-translate-y-1 transition-all duration-300"
              >
                Browse Properties
                <ArrowRight className="w-5 h-5" />
              </Link>
            </div>
          </div>
        </div>

      </div>
    </div>
  );
}
