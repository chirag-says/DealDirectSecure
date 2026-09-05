/**
 * Web app manifest.
 *
 * The `any` icons are transparent so they sit correctly on a browser's own
 * background; the `maskable` one is opaque with an 18% margin because Android
 * crops maskable icons to a circle and anything inside that margin is lost.
 * The two purposes must be separate files — declaring one icon as
 * "any maskable" gets it cropped in both contexts.
 */
export default function manifest() {
    return {
        name: 'DealDirect — Buy & Sell Properties Without Middlemen',
        short_name: 'DealDirect',
        description:
            "India's platform for buying, selling, and renting properties directly from owners — no brokerage, no middlemen.",
        start_url: '/',
        display: 'standalone',
        background_color: '#ffffff',
        theme_color: '#f22829',
        lang: 'en-IN',
        categories: ['business', 'lifestyle', 'shopping'],
        icons: [
            { src: '/icons/icon-192.png', sizes: '192x192', type: 'image/png', purpose: 'any' },
            { src: '/icons/icon-512.png', sizes: '512x512', type: 'image/png', purpose: 'any' },
            { src: '/icons/maskable-512.png', sizes: '512x512', type: 'image/png', purpose: 'maskable' },
        ],
    };
}
