import { cva, type VariantProps } from 'class-variance-authority'
import type * as React from 'react'

import { cn } from '../../lib/utils'

/**
 * Badge is the one place severity colour is allowed: badges and small marks
 * only, never large surfaces (§7).
 */
export const badgeVariants = cva(
  'inline-flex h-5 items-center gap-1 rounded-[5px] border px-1.5 text-[11px] font-medium whitespace-nowrap',
  {
    variants: {
      tone: {
        neutral: 'border-border-strong bg-surface text-muted',
        critical: 'border-critical/30 bg-critical/10 text-critical',
        high: 'border-high/30 bg-high/10 text-high',
        medium: 'border-medium/30 bg-medium/10 text-medium',
        low: 'border-low/30 bg-low/10 text-low',
        ok: 'border-ok/30 bg-ok/10 text-ok',
      },
    },
    defaultVariants: {
      tone: 'neutral',
    },
  },
)

type BadgeProps = React.ComponentProps<'span'> & VariantProps<typeof badgeVariants>

export function Badge({ className, tone, ...props }: BadgeProps) {
  return (
    <span
      data-slot="badge"
      className={cn(badgeVariants({ tone }), className)}
      {...props}
    />
  )
}
