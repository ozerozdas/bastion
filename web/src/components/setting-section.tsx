import type { ReactNode } from 'react'

import { Badge } from './ui/badge'

/** SettingSection is one setting: its name, its state and its control. */
export function SettingSection({
  title,
  on,
  children,
}: {
  title: string
  /** On/off state for the badge; omitted when the setting is not a toggle. */
  on?: boolean
  children: ReactNode
}) {
  return (
    <section
      aria-label={title}
      className="flex flex-col gap-1.5 rounded-md border border-border-subtle bg-bg p-3"
    >
      <div className="flex items-center gap-2">
        <h3 className="text-[0.8125rem] font-semibold">{title}</h3>
        {on === undefined ? null : (
          <Badge tone={on ? 'ok' : 'neutral'}>{on ? 'On' : 'Off'}</Badge>
        )}
      </div>
      {children}
    </section>
  )
}
