import type { ReactNode } from 'react'

type EmptyStateProps = {
  title: string
  /** What the user should do next; every empty state explains this (§7). */
  body: string
  children?: ReactNode
}

export function EmptyState({ title, body, children }: EmptyStateProps) {
  return (
    <section className="flex flex-col items-start gap-3 rounded-card border border-border-subtle bg-surface p-8">
      <h2 className="text-[15px] font-semibold tracking-[-0.01em]">{title}</h2>
      <p className="max-w-[52ch] text-muted">{body}</p>
      {children ? (
        <div className="mt-2 flex flex-wrap items-center gap-2">{children}</div>
      ) : null}
    </section>
  )
}
