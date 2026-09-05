'use client';

import React, { useState, useEffect, useMemo, useRef, useCallback } from "react";
import Link from "next/link";
import {
    Building2, ClipboardList, Gift, Lock,
    Search, X, Plus, Minus, ArrowRight, MessageCircle, LifeBuoy,
} from "lucide-react";
import { faqCategories, allFaqs } from "./faqData";

// faqData is serialisable, so it carries an icon *key*. Resolve it here.
const ICONS = {
    building: Building2,
    list: ClipboardList,
    gift: Gift,
    lock: Lock,
};

/**
 * Collapsible answer.
 *
 * Uses a 0fr → 1fr grid row rather than max-height. A max-height animation has
 * to guess how tall the content is, and the previous `max-h-96` silently clipped
 * any answer taller than 384px. A grid row animates to the content's real height.
 */
function Answer({ id, labelledBy, open, children }) {
    return (
        // Deliberately not `hidden`: display:none would kill the transition, and
        // keeping the text in the DOM means Ctrl+F finds it and crawlers read it
        // for the FAQPage rich result. The button's aria-expanded carries state.
        <div
            id={id}
            aria-labelledby={labelledBy}
            className={`grid transition-[grid-template-rows] duration-300 ease-out ${open ? 'grid-rows-[1fr]' : 'grid-rows-[0fr]'}`}
        >
            <div className="overflow-hidden">
                <p className="px-5 pb-5 pl-14 text-[15px] leading-relaxed text-slate-600 max-w-[65ch]">
                    {children}
                </p>
            </div>
        </div>
    );
}

function QuestionRow({ item, index, open, onToggle }) {
    const btnId = `faq-q-${item.id}`;
    const panelId = `faq-a-${item.id}`;

    return (
        <div
            id={item.id}
            className={`scroll-mt-28 rounded-xl border transition-colors ${open ? 'border-slate-300 bg-white shadow-sm' : 'border-slate-200 bg-white hover:border-slate-300'}`}
        >
            <h3>
                <button
                    id={btnId}
                    type="button"
                    onClick={onToggle}
                    aria-expanded={open}
                    aria-controls={panelId}
                    className="flex w-full items-start gap-4 px-5 py-4 text-left rounded-xl focus:outline-none focus-visible:ring-2 focus-visible:ring-red-500 focus-visible:ring-offset-2"
                >
                    {/* Decorative counter — hidden from the accessible name so a
                        screen reader announces the question, not "01 What is…". */}
                    <span aria-hidden="true" className="mt-0.5 flex h-6 w-6 shrink-0 items-center justify-center rounded-md bg-slate-100 text-[11px] font-semibold tabular-nums text-slate-500">
                        {String(index + 1).padStart(2, '0')}
                    </span>
                    <span className={`flex-1 text-[15px] font-semibold leading-snug ${open ? 'text-red-600' : 'text-slate-900'}`}>
                        {item.q}
                    </span>
                    <span className="mt-0.5 shrink-0 text-slate-400">
                        {open ? <Minus className="h-4 w-4" /> : <Plus className="h-4 w-4" />}
                    </span>
                </button>
            </h3>
            <Answer id={panelId} labelledBy={btnId} open={open}>{item.a}</Answer>
        </div>
    );
}

export default function FAQContent() {
    const [openIds, setOpenIds] = useState(() => new Set());
    const [query, setQuery] = useState("");
    const [activeCategory, setActiveCategory] = useState(faqCategories[0].id);
    const sectionRefs = useRef({});

    const toggle = useCallback((id) => {
        setOpenIds((prev) => {
            const next = new Set(prev);
            next.has(id) ? next.delete(id) : next.add(id);
            return next;
        });
    }, []);

    // Deep links (/faq#report-listing) open the question and scroll to it, so a
    // link from support or a help article lands on the answer, not the top of
    // a page where every answer is closed.
    useEffect(() => {
        const target = decodeURIComponent(window.location.hash.slice(1));
        if (!target) return;
        if (!allFaqs.some((f) => f.id === target)) return;
        setOpenIds(new Set([target]));
        requestAnimationFrame(() => {
            document.getElementById(target)?.scrollIntoView({ block: 'center' });
        });
    }, []);

    const q = query.trim().toLowerCase();

    const results = useMemo(() => {
        if (!q) return faqCategories;
        return faqCategories
            .map((cat) => ({
                ...cat,
                questions: cat.questions.filter(
                    (item) =>
                        item.q.toLowerCase().includes(q) || item.a.toLowerCase().includes(q)
                ),
            }))
            .filter((cat) => cat.questions.length > 0);
    }, [q]);

    const resultCount = results.reduce((n, cat) => n + cat.questions.length, 0);

    // While searching, open every match — a hit you still have to click is not
    // an answer. Reverts to whatever the user had open when the box is cleared.
    const isOpen = (id) => (q ? true : openIds.has(id));

    // Highlight the category the reader is actually looking at, rather than the
    // last one they clicked.
    useEffect(() => {
        if (q) return;
        const obs = new IntersectionObserver(
            (entries) => {
                const visible = entries
                    .filter((e) => e.isIntersecting)
                    .sort((a, b) => a.boundingClientRect.top - b.boundingClientRect.top)[0];
                if (visible) setActiveCategory(visible.target.dataset.categoryId);
            },
            { rootMargin: '-30% 0px -60% 0px' }
        );
        Object.values(sectionRefs.current).forEach((el) => el && obs.observe(el));
        return () => obs.disconnect();
    }, [q]);

    return (
        <div className="min-h-screen bg-white text-slate-900">

            {/* ── Header ────────────────────────────────────────────────────
                Left-aligned and compact. The old hero centred five elements
                across a full viewport before showing a single answer. */}
            <header className="border-b border-slate-200 bg-slate-50">
                <div className="mx-auto grid max-w-6xl gap-10 px-6 py-14 lg:grid-cols-[1.15fr_1fr] lg:items-end lg:py-20">
                    <div>
                        <span className="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white px-3 py-1 text-xs font-semibold uppercase tracking-wider text-slate-500">
                            <LifeBuoy className="h-3.5 w-3.5" />
                            Help Centre
                        </span>
                        <h1 className="mt-5 text-4xl font-bold leading-[1.1] tracking-tight text-slate-900 sm:text-5xl">
                            Questions, answered.
                        </h1>
                        <p className="mt-4 max-w-[52ch] text-lg leading-relaxed text-slate-600">
                            Everything about listing a property on DealDirect, earning rewards,
                            and keeping your details private.
                        </p>
                    </div>

                    <div className="lg:pb-2">
                        <label htmlFor="faq-search" className="sr-only">Search the FAQs</label>
                        <div className="relative">
                            <Search className="pointer-events-none absolute left-4 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400" />
                            <input
                                id="faq-search"
                                type="text"
                                value={query}
                                onChange={(e) => setQuery(e.target.value)}
                                onKeyDown={(e) => e.key === 'Escape' && setQuery('')}
                                placeholder="Search — brokerage, rewards, editing a post…"
                                className="w-full rounded-xl border border-slate-300 bg-white py-3.5 pl-11 pr-11 text-[15px] text-slate-900 placeholder:text-slate-400 focus:border-red-500 focus:outline-none focus:ring-2 focus:ring-red-100"
                            />
                            {query && (
                                <button
                                    type="button"
                                    onClick={() => setQuery('')}
                                    aria-label="Clear search"
                                    className="absolute right-3 top-1/2 -translate-y-1/2 rounded-md p-1.5 text-slate-400 hover:bg-slate-100 hover:text-slate-700"
                                >
                                    <X className="h-4 w-4" />
                                </button>
                            )}
                        </div>
                        <p className="mt-2.5 h-5 text-xs text-slate-500" aria-live="polite">
                            {q
                                ? `${resultCount} ${resultCount === 1 ? 'answer' : 'answers'} for “${query.trim()}”`
                                : `${allFaqs.length} answers across ${faqCategories.length} topics`}
                        </p>
                    </div>
                </div>
            </header>

            {/* ── Index + questions ─────────────────────────────────────── */}
            <div className="mx-auto max-w-6xl px-6 py-14 lg:py-20">
                <div className="grid gap-12 lg:grid-cols-[220px_1fr] lg:gap-16">

                    {/* Category index — sticky below the fixed navbar (h-16 / lg:h-20) */}
                    <nav aria-label="FAQ topics" className="lg:sticky lg:top-28 lg:self-start">
                        <p className="mb-3 text-xs font-semibold uppercase tracking-wider text-slate-400">
                            Topics
                        </p>
                        <ul className="flex gap-2 overflow-x-auto pb-2 scrollbar-hide lg:block lg:space-y-1 lg:overflow-visible lg:pb-0">
                            {faqCategories.map((cat) => {
                                const Icon = ICONS[cat.icon];
                                const active = !q && activeCategory === cat.id;
                                return (
                                    <li key={cat.id} className="shrink-0">
                                        <a
                                            href={`#cat-${cat.id}`}
                                            onClick={() => setActiveCategory(cat.id)}
                                            className={`flex items-center gap-2.5 whitespace-nowrap rounded-lg px-3 py-2 text-sm font-medium transition-colors ${active
                                                ? 'bg-red-50 text-red-700'
                                                : 'text-slate-600 hover:bg-slate-100 hover:text-slate-900'
                                                }`}
                                        >
                                            <Icon className="h-4 w-4 shrink-0" />
                                            {cat.title}
                                            <span className="ml-auto hidden text-xs tabular-nums text-slate-400 lg:inline">
                                                {cat.questions.length}
                                            </span>
                                        </a>
                                    </li>
                                );
                            })}
                        </ul>
                    </nav>

                    {/* Questions */}
                    <div className="min-w-0">
                        {resultCount === 0 ? (
                            <div className="rounded-2xl border border-dashed border-slate-300 px-6 py-16 text-center">
                                <div className="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-full bg-slate-100">
                                    <Search className="h-5 w-5 text-slate-400" />
                                </div>
                                <p className="text-lg font-semibold text-slate-900">
                                    Nothing matches “{query.trim()}”
                                </p>
                                <p className="mx-auto mt-2 max-w-sm text-sm text-slate-500">
                                    Try a shorter word, or ask us directly — we answer every message.
                                </p>
                                <div className="mt-6 flex flex-wrap justify-center gap-3">
                                    <button
                                        type="button"
                                        onClick={() => setQuery('')}
                                        className="rounded-lg border border-slate-300 px-4 py-2.5 text-sm font-semibold text-slate-700 hover:bg-slate-50"
                                    >
                                        Clear search
                                    </button>
                                    <Link
                                        href="/contact"
                                        className="inline-flex items-center gap-2 rounded-lg bg-red-600 px-4 py-2.5 text-sm font-semibold text-white hover:bg-red-700"
                                    >
                                        Ask support <ArrowRight className="h-4 w-4" />
                                    </Link>
                                </div>
                            </div>
                        ) : (
                            <div className="space-y-14">
                                {results.map((cat) => {
                                    const Icon = ICONS[cat.icon];
                                    return (
                                        <section
                                            key={cat.id}
                                            id={`cat-${cat.id}`}
                                            data-category-id={cat.id}
                                            ref={(el) => { sectionRefs.current[cat.id] = el; }}
                                            className="scroll-mt-28"
                                            aria-labelledby={`cat-h-${cat.id}`}
                                        >
                                            <div className="mb-5 flex items-start gap-3 border-b border-slate-200 pb-4">
                                                <Icon className="mt-1 h-5 w-5 shrink-0 text-slate-400" />
                                                <div>
                                                    <h2 id={`cat-h-${cat.id}`} className="text-xl font-bold tracking-tight text-slate-900">
                                                        {cat.title}
                                                    </h2>
                                                    <p className="mt-1 text-sm text-slate-500">{cat.blurb}</p>
                                                </div>
                                            </div>
                                            <div className="space-y-2.5">
                                                {cat.questions.map((item, i) => (
                                                    <QuestionRow
                                                        key={item.id}
                                                        item={item}
                                                        index={i}
                                                        open={isOpen(item.id)}
                                                        onToggle={() => toggle(item.id)}
                                                    />
                                                ))}
                                            </div>
                                        </section>
                                    );
                                })}
                            </div>
                        )}
                    </div>
                </div>
            </div>

            {/* ── Contact band ──────────────────────────────────────────── */}
            <section className="border-t border-slate-200 bg-slate-50">
                <div className="mx-auto flex max-w-6xl flex-col gap-6 px-6 py-14 sm:flex-row sm:items-center sm:justify-between">
                    <div className="flex items-start gap-4">
                        <span className="mt-0.5 flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-white ring-1 ring-slate-200">
                            <MessageCircle className="h-5 w-5 text-red-600" />
                        </span>
                        <div>
                            <h2 className="text-xl font-bold tracking-tight text-slate-900">
                                Still stuck?
                            </h2>
                            <p className="mt-1 max-w-[48ch] text-[15px] text-slate-600">
                                Send us the details and a person will reply. No bots, no ticket queue.
                            </p>
                        </div>
                    </div>
                    <div className="flex shrink-0 flex-wrap gap-3">
                        <Link
                            href="/contact"
                            className="inline-flex items-center gap-2 rounded-xl bg-red-600 px-6 py-3 text-sm font-semibold text-white shadow-sm transition-colors hover:bg-red-700 focus:outline-none focus-visible:ring-2 focus-visible:ring-red-500 focus-visible:ring-offset-2"
                        >
                            Contact support <ArrowRight className="h-4 w-4" />
                        </Link>
                        <Link
                            href="/about"
                            className="inline-flex items-center rounded-xl border border-slate-300 bg-white px-6 py-3 text-sm font-semibold text-slate-700 transition-colors hover:bg-slate-50"
                        >
                            About us
                        </Link>
                    </div>
                </div>
            </section>
        </div>
    );
}
