import { cn } from '../../lib/utils'

/**
 * Switch is a binary setting's control. The accessible name is the setting it
 * changes and stays the same while it flips; the state lives in aria-checked.
 */
export function Switch({
  checked,
  disabled = false,
  label,
  onCheckedChange,
  className,
}: {
  checked: boolean
  disabled?: boolean
  /** Accessible name, e.g. the module's title. */
  label: string
  onCheckedChange: (checked: boolean) => void
  className?: string
}) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-label={label}
      title={label}
      disabled={disabled}
      onClick={() => onCheckedChange(!checked)}
      className={cn(
        'relative inline-flex h-[18px] w-8 shrink-0 items-center rounded-full transition-colors focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-muted disabled:pointer-events-none disabled:opacity-50',
        checked ? 'bg-accent' : 'bg-border-strong',
        className,
      )}
    >
      <span
        aria-hidden="true"
        className={cn(
          'size-3.5 rounded-full bg-surface shadow-sm transition-transform',
          checked ? 'translate-x-[15px]' : 'translate-x-[2px]',
        )}
      />
    </button>
  )
}
