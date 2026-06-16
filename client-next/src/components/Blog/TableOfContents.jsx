'use client';
import { useEffect, useState, useRef } from 'react';
import { FiList } from 'react-icons/fi';

export default function TableOfContents({ content }) {
    const [headings, setHeadings] = useState([]);
    const [activeId, setActiveId] = useState('');
    const observerRef = useRef(null);

    useEffect(() => {
        // Parse headings from rendered markdown
        const articleEl = document.querySelector('#blog-content');
        if (!articleEl) return;

        const els = articleEl.querySelectorAll('h2, h3');
        const items = [];
        els.forEach((el, i) => {
            const id = el.id || `heading-${i}`;
            el.id = id;
            items.push({ id, text: el.textContent, level: el.tagName.toLowerCase() });
        });
        setHeadings(items);

        // Intersection observer for active heading
        observerRef.current = new IntersectionObserver(
            (entries) => {
                entries.forEach((entry) => {
                    if (entry.isIntersecting) setActiveId(entry.target.id);
                });
            },
            { rootMargin: '-80px 0px -60% 0px' }
        );
        els.forEach((el) => observerRef.current.observe(el));

        return () => observerRef.current?.disconnect();
    }, [content]);

    if (headings.length < 2) return null;

    return (
        <nav className="bg-gray-50 border border-gray-200 rounded-2xl p-5 sticky top-24">
            <h3 className="flex items-center gap-2 font-bold text-gray-800 text-sm mb-4">
                <FiList className="w-4 h-4 text-blue-600" />
                Table of Contents
            </h3>
            <ul className="space-y-2">
                {headings.map((h) => (
                    <li key={h.id} className={h.level === 'h3' ? 'pl-4' : ''}>
                        <a
                            href={`#${h.id}`}
                            onClick={(e) => {
                                e.preventDefault();
                                document.getElementById(h.id)?.scrollIntoView({ behavior: 'smooth', block: 'start' });
                            }}
                            className={`block text-sm py-0.5 transition-colors truncate ${activeId === h.id
                                    ? 'text-blue-600 font-semibold'
                                    : 'text-gray-500 hover:text-gray-900'
                                }`}
                        >
                            {h.text}
                        </a>
                    </li>
                ))}
            </ul>
        </nav>
    );
}
