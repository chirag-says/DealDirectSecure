/**
 * Shared layout for DealDirect's legal pages (privacy notice, terms of use).
 *
 * Server-rendered, so search engines and screen readers get the full text,
 * and print-friendly. Sections are numbered from their order; the contents
 * list links to each by id.
 *
 * <ToConfirm> marks a fact still awaited from the operator (Agrawal Business
 * Network LLP). It renders as a highlighted "[To be confirmed: ...]" so a page
 * carrying one cannot be mistaken for final, the same convention as
 * /delete-account. Remove every marker, with the confirmed fact, before
 * publishing.
 */

export function ToConfirm({ children }) {
  return (
    <mark className="rounded bg-amber-100 px-1 text-amber-900">[To be confirmed: {children}]</mark>
  );
}

export const legalLink = "font-medium text-blue-700 underline underline-offset-2 hover:text-blue-900";

/** A two-or-more column table for itemised data, purposes, vendors, retention. */
export function LegalTable({ head, rows, caption }) {
  return (
    <div className="my-4 overflow-x-auto rounded-xl border border-slate-200">
      <table className="w-full min-w-[560px] border-collapse text-left text-sm">
        {caption && <caption className="sr-only">{caption}</caption>}
        <thead className="bg-slate-50 text-slate-700">
          <tr>
            {head.map((h) => (
              <th key={h} scope="col" className="border-b border-slate-200 px-4 py-2.5 font-semibold">
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="align-top text-slate-700">
          {rows.map((row, i) => (
            <tr key={i} className="border-b border-slate-100 last:border-0">
              {row.map((cell, j) => (
                <td key={j} className={`px-4 py-3 leading-relaxed ${j === 0 ? "font-medium text-slate-900" : ""}`}>
                  {cell}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/**
 * @param {{
 *   title: string, summary: React.ReactNode, effective: string, updated: string,
 *   sections: { id: string, title: string, body: React.ReactNode }[],
 *   related?: { href: string, label: string }[],
 * }} props
 */
export default function LegalDocument({ title, summary, effective, updated, sections, related = [] }) {
  return (
    <div className="min-h-screen bg-slate-50 font-sans text-slate-900">
      <header className="border-b border-slate-200 bg-white">
        <div className="mx-auto max-w-6xl px-4 py-12 sm:px-6 sm:py-16">
          <p className="text-xs font-semibold uppercase tracking-[0.12em] text-slate-500">DealDirect · Legal</p>
          <h1 className="mt-2 text-3xl font-bold tracking-tight sm:text-4xl">{title}</h1>
          <div className="mt-4 max-w-3xl text-base leading-relaxed text-slate-600">{summary}</div>
          <dl className="mt-6 flex flex-wrap gap-x-8 gap-y-2 text-sm text-slate-500">
            <div className="flex gap-2"><dt>Effective:</dt><dd className="font-medium text-slate-700">{effective}</dd></div>
            <div className="flex gap-2"><dt>Last updated:</dt><dd className="font-medium text-slate-700">{updated}</dd></div>
          </dl>
        </div>
      </header>

      <div className="mx-auto flex max-w-6xl flex-col gap-10 px-4 py-10 sm:px-6 lg:flex-row lg:py-14">
        <nav aria-label="Contents" className="lg:w-64 lg:flex-shrink-0 print:hidden">
          <div className="lg:sticky lg:top-28">
            <p className="mb-3 text-xs font-semibold uppercase tracking-[0.12em] text-slate-500">Contents</p>
            <ol className="space-y-1.5 text-sm">
              {sections.map((s, i) => (
                <li key={s.id}>
                  <a href={`#${s.id}`} className="flex gap-2 rounded-md px-2 py-1 text-slate-600 hover:bg-white hover:text-slate-900">
                    <span className="w-5 flex-shrink-0 tabular-nums text-slate-400">{i + 1}.</span>
                    <span>{s.title}</span>
                  </a>
                </li>
              ))}
            </ol>
            {related.length > 0 && (
              <div className="mt-6 border-t border-slate-200 pt-4 text-sm">
                <p className="mb-2 text-xs font-semibold uppercase tracking-[0.12em] text-slate-500">Related</p>
                <ul className="space-y-1.5">
                  {related.map((r) => (
                    <li key={r.href}><a href={r.href} className={legalLink}>{r.label}</a></li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        </nav>

        <article className="min-w-0 flex-1 rounded-2xl border border-slate-200 bg-white px-5 py-8 sm:px-10 sm:py-10">
          {sections.map((s, i) => (
            <section key={s.id} id={s.id} aria-labelledby={`${s.id}-title`} className="scroll-mt-28 border-b border-slate-100 py-8 first:pt-0 last:border-0 last:pb-0">
              <h2 id={`${s.id}-title`} className="text-xl font-semibold text-slate-900">
                <span className="mr-2 tabular-nums text-slate-400">{i + 1}.</span>
                {s.title}
              </h2>
              <div className="legal-body mt-4 space-y-4 text-[15px] leading-relaxed text-slate-700 [&_li]:pl-1 [&_ol]:list-decimal [&_ol]:space-y-2 [&_ol]:pl-5 [&_ul]:list-disc [&_ul]:space-y-2 [&_ul]:pl-5 [&_h3]:mt-6 [&_h3]:font-semibold [&_h3]:text-slate-900">
                {s.body}
              </div>
            </section>
          ))}
        </article>
      </div>
    </div>
  );
}
