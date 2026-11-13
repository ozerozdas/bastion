import type * as React from 'react'

import { cn } from '../../lib/utils'

type CheckboxProps = Omit<React.ComponentProps<'input'>, 'type'> & {
  /** Shows the mixed state, e.g. some rows selected. */
  indeterminate?: boolean
}

/** Checkbox is a native checkbox that can also show the mixed (indeterminate) state. */
export function Checkbox({ indeterminate = false, className, ...props }: CheckboxProps) {
  // Callers supply cursor and alignment via className (Projects deliberately has none).
  return (
    <input
      type="checkbox"
      ref={(node) => {
        if (node) node.indeterminate = indeterminate
      }}
      className={cn('size-3.5 accent-accent', className)}
      {...props}
    />
  )
}
