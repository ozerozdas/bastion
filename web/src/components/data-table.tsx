import {
  Fragment,
  useEffect,
  useRef,
  useState,
  type ReactNode,
  type Ref,
  type RefObject,
} from 'react'

import { cn } from '../lib/utils'
import { Checkbox } from './ui/checkbox'

export type DataTableColumn<T> = {
  /** Stable id for React keys; not shown. */
  id: string
  header: ReactNode
  /**
   * The cell for one row. Omit it when the caller renders its own rows with
   * `renderRow` and only the header comes from this definition.
   */
  cell?: (row: T) => ReactNode
  /** Extra classes for the header cell. */
  headerClassName?: string
  /** Extra classes for every body cell in this column. */
  cellClassName?: string
  /** A title for the body cell, for values that truncate. */
  cellTitle?: (row: T) => string | undefined
}

export type DataTableRowSelection = {
  checked: boolean
  onChange: () => void
  label: string
  /** Classes for the checkbox cell, e.g. "py-2". */
  cellClassName?: string
  /** Classes for the checkbox itself, e.g. "cursor-pointer align-middle". */
  checkboxClassName?: string
}

export type DataTableSelection<T> = {
  /** The select-all checkbox in the header. */
  all: {
    checked: boolean
    indeterminate?: boolean
    onChange: () => void
    label: string
    checkboxClassName?: string
  }
  row: (row: T) => DataTableRowSelection
  /** Extra classes for the header cell, e.g. "w-6". */
  headerClassName?: string
}

export type DataTableProps<T> = {
  rows: readonly T[]
  columns: readonly DataTableColumn<T>[]
  rowKey: (row: T) => string
  selection?: DataTableSelection<T>
  /** Makes a row open on click, Enter or Space; omitted rows are not interactive. */
  onRowActivate?: (row: T, index: number) => void
  /**
   * Renders the row itself, for rows that own their mutations or add inline
   * detail rows below the main one (Projects does both).
   */
  renderRow?: (row: T, index: number) => ReactNode
  /** The tbody, so a page can restore focus after it removes a row (issue #75). */
  bodyRef?: Ref<HTMLTableSectionElement>
}

/** DataTable is the shared table shell: header, optional selection, body. */
export function DataTable<T>({
  rows,
  columns,
  rowKey,
  selection,
  onRowActivate,
  renderRow,
  bodyRef,
}: DataTableProps<T>) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-[13px]">
        <thead className="text-xs text-faint">
          <tr>
            {selection ? (
              <th className={cn('pb-2', selection.headerClassName)}>
                <Checkbox
                  aria-label={selection.all.label}
                  checked={selection.all.checked}
                  indeterminate={selection.all.indeterminate ?? false}
                  onChange={selection.all.onChange}
                  className={selection.all.checkboxClassName}
                />
              </th>
            ) : null}
            {columns.map((column) => (
              <th
                key={column.id}
                className={cn('pb-2 font-medium', column.headerClassName)}
              >
                {column.header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody ref={bodyRef} className="divide-y divide-border-subtle">
          {rows.map((row, index) => (
            <Fragment key={rowKey(row)}>
              {renderRow ? (
                renderRow(row, index)
              ) : (
                <DataTableRow
                  selection={selection?.row(row)}
                  onActivate={
                    onRowActivate ? () => onRowActivate(row, index) : undefined
                  }
                >
                  {columns.map((column) => (
                    <td
                      key={column.id}
                      className={column.cellClassName}
                      title={column.cellTitle?.(row)}
                    >
                      {column.cell?.(row)}
                    </td>
                  ))}
                </DataTableRow>
              )}
            </Fragment>
          ))}
        </tbody>
      </table>
    </div>
  )
}

/** DataTableRow is the row shell, exported for callers that render rows themselves. */
export function DataTableRow({
  selection,
  onActivate,
  children,
}: {
  selection?: DataTableRowSelection
  onActivate?: () => void
  children: ReactNode
}) {
  return (
    <tr
      tabIndex={onActivate ? 0 : undefined}
      onClick={onActivate}
      onKeyDown={
        onActivate
          ? (event) => {
              if (event.key === 'Enter' || event.key === ' ') {
                event.preventDefault()
                onActivate()
              }
            }
          : undefined
      }
      className={
        onActivate
          ? 'cursor-pointer align-top hover:bg-hover focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-muted'
          : undefined
      }
    >
      {selection ? (
        // The checkbox cell must not open the row's detail view.
        <td
          className={selection.cellClassName}
          onClick={
            onActivate ? (event) => event.stopPropagation() : undefined
          }
          onKeyDown={
            onActivate ? (event) => event.stopPropagation() : undefined
          }
        >
          <Checkbox
            aria-label={selection.label}
            checked={selection.checked}
            onChange={selection.onChange}
            className={selection.checkboxClassName}
          />
        </td>
      ) : null}
      {children}
    </tr>
  )
}

/**
 * useRowRemovalFocus keeps keyboard focus in the table after an action removes
 * the focused row (#75). Record the row before the request: the refresh can
 * unmount the drawer, and its own focus restore, before the request resolves.
 */
export function useRowRemovalFocus<T>({
  rows,
  rowKey,
  fallback,
  onRemoved,
}: {
  /** The refreshed list; undefined until it has loaded. */
  rows: readonly T[] | undefined
  rowKey: (row: T) => string
  /** Where focus goes when the removing row was the last one. */
  fallback: RefObject<HTMLElement | null>
  /** Runs once the refreshed list no longer has the row, e.g. to close the drawer. */
  onRemoved?: () => void
}): {
  bodyRef: RefObject<HTMLTableSectionElement | null>
  /** Call before a request that may remove the row. */
  beginRemoval: (key: string, index: number) => void
  /** Call when that request failed, so the row stays. */
  cancelRemoval: () => void
} {
  const [removal, setRemoval] = useState<{ key: string; index: number } | null>(
    null,
  )
  const bodyRef = useRef<HTMLTableSectionElement>(null)
  // ReportsPage recreates these props every render; keep the effect keyed on
  // the data alone, with the latest callbacks in refs.
  const rowKeyRef = useRef(rowKey)
  const fallbackTarget = useRef(fallback)
  const onRemovedRef = useRef(onRemoved)

  useEffect(() => {
    rowKeyRef.current = rowKey
    fallbackTarget.current = fallback
    onRemovedRef.current = onRemoved
  })

  useEffect(() => {
    if (removal === null || rows === undefined) return
    // The refresh that drops the row is the moment to move: until it lands,
    // the row (and the focus the drawer gave back) is still valid.
    if (rows.some((row) => rowKeyRef.current(row) === removal.key)) return
    setRemoval(null)
    onRemovedRef.current?.()
    // A click or Tab after the close wins over restoring focus.
    if (document.activeElement !== document.body && document.activeElement !== null) {
      return
    }

    const tableRows = bodyRef.current?.rows
    if (tableRows !== undefined && tableRows.length > 0) {
      // The row after the removed one slides into its place; if it was the
      // last row, this is the one before it.
      tableRows[Math.min(removal.index, tableRows.length - 1)]?.focus()
      return
    }
    fallbackTarget.current.current?.focus()
  }, [rows, removal])

  return {
    bodyRef,
    beginRemoval: (key, index) => setRemoval({ key, index }),
    cancelRemoval: () => setRemoval(null),
  }
}
