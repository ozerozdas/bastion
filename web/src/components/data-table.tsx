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
import { useT } from '../lib/i18n'
import { Checkbox } from './ui/checkbox'

/** SortDirection is the direction a sortable header asks for. */
export type SortDirection = 'asc' | 'desc'

/** DataTableSort is the column and direction a table is ordered by. */
export type DataTableSort = {
  /** The column's sortKey, or its id when it has none. */
  columnId: string
  direction: SortDirection
}

/**
 * MobileColumnRole says how a column joins the compact card a row becomes
 * below md (48rem). A column without a role is hidden in that layout.
 */
export type MobileColumnRole =
  | 'primary'
  | 'secondary'
  | 'status'
  | 'counts'
  | 'actions'
  | 'hidden'

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
  /**
   * Makes the header a button that reports a new sort through onSortChange.
   * A column with sortValue is ordered in the browser; one without is ordered
   * by the caller (the server, for a paginated list).
   */
  sortable?: boolean
  /** The API's name for the column when it differs from id. */
  sortKey?: string
  /** The direction the first activation asks for; ascending by default. */
  defaultSortDirection?: SortDirection
  /** The value browser sorting compares. */
  sortValue?: (row: T) => string | number
  /**
   * A plain-text name for the column in the mobile sort menu, for headers that
   * are not already a string.
   */
  sortLabel?: string
  /**
   * How the column takes part in the stacked card layout below md. Cards are
   * only built for a DataTable with `mobileCards`; columns left unmarked are
   * hidden there.
   */
  mobile?: MobileColumnRole
  /** A label the card shows before this cell's value below md. */
  mobileLabel?: string
  /**
   * Says this cell has no value for the row, so the card layout can drop it
   * instead of showing an empty labelled line.
   */
  cellEmpty?: (row: T) => boolean
}

/** mobileCellProps are the data attributes the card layout in styles.css reads. */
export function mobileCellProps<T>(column: DataTableColumn<T>): {
  role: 'cell'
  'data-mobile': MobileColumnRole
  'data-label'?: string
} {
  return {
    role: 'cell',
    'data-mobile': column.mobile ?? 'hidden',
    ...(column.mobileLabel === undefined
      ? {}
      : { 'data-label': column.mobileLabel }),
  }
}

/**
 * MobileCellLabel is a card's field name, a real span so the table keeps its
 * semantics below md instead of drawing the name in CSS.
 */
export function MobileCellLabel({ label }: { label?: string }) {
  if (label === undefined) return null
  return <span className="data-table-card-label">{label}</span>
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
  /** The current sort; sortable headers render a button and aria-sort. */
  sort?: DataTableSort
  /** Reports the sort a header activation asks for. */
  onSortChange?: (sort: DataTableSort) => void
  /** Orders rows in the browser by the active column's sortValue. */
  clientSort?: boolean
  /**
   * Below md each row becomes a compact card and the header row gives way to
   * the select-all control; at md and up the table is unchanged.
   */
  mobileCards?: boolean
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
  sort,
  onSortChange,
  clientSort,
  mobileCards,
}: DataTableProps<T>) {
  const t = useT()
  const ordered = clientSort && sort !== undefined
    ? sortTableRows(rows, columns, sort)
    : rows
  const cardMode = mobileCards === true
  // A card hides the columns it has no role for, so their sort waits for the
  // header row at md and up.
  const sortableColumns =
    cardMode && onSortChange !== undefined
      ? columns.filter(
          (column) =>
            column.sortable === true &&
            column.mobile !== undefined &&
            column.mobile !== 'hidden',
        )
      : []
  const activeSort =
    sort === undefined
      ? undefined
      : sortableColumns.find(
          (column) => columnSortKey(column) === sort.columnId,
        )
  const sortDirection: SortDirection =
    sort?.direction === 'desc' ? 'desc' : 'asc'
  const nextDirection: SortDirection =
    activeSort === undefined
      ? sortableColumns[0]?.defaultSortDirection ?? 'asc'
      : sortDirection === 'asc'
        ? 'desc'
        : 'asc'

  return (
    <>
      {sortableColumns.length > 0 ? (
        <div className="mb-2 flex items-center gap-2 md:hidden">
          <label className="flex min-w-0 flex-1 items-center gap-2 text-xs text-muted">
            <span className="shrink-0">{t('table.sortBy')}</span>
            <select
              value={activeSort === undefined ? '' : sort?.columnId}
              onChange={(event) => {
                const column = sortableColumns.find(
                  (candidate) =>
                    columnSortKey(candidate) === event.target.value,
                )
                if (column !== undefined) {
                  onSortChange?.(nextTableSort(sort, column))
                }
              }}
              className="h-8 min-w-0 flex-1 rounded-md border border-border-strong bg-surface px-2 text-[0.8125rem] text-fg"
            >
              {activeSort === undefined ? (
                <option value="">{t('table.defaultOrder')}</option>
              ) : null}
              {sortableColumns.map((column) => (
                <option key={column.id} value={columnSortKey(column)}>
                  {sortOptionLabel(column)}
                </option>
              ))}
            </select>
          </label>
          <button
            type="button"
            aria-label={
              nextDirection === 'asc'
                ? t('table.sortAscending')
                : t('table.sortDescending')
            }
            onClick={() => {
              const column = activeSort ?? sortableColumns[0]
              if (column === undefined) return
              onSortChange?.(
                nextTableSort(
                  activeSort === undefined ? undefined : sort,
                  column,
                ),
              )
            }}
            className="flex h-8 shrink-0 items-center justify-center rounded-md border border-border-strong bg-surface px-2 text-[0.8125rem] text-muted focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-muted"
          >
            <span aria-hidden="true">{nextDirection === 'asc' ? '↑' : '↓'}</span>
          </button>
        </div>
      ) : null}
      <div className="overflow-x-auto">
        <table
          role={cardMode ? 'table' : undefined}
          className={cn(
            'w-full text-left text-[0.875rem]',
            cardMode && 'data-table-cards',
          )}
        >
          <thead role={cardMode ? 'rowgroup' : undefined} className="text-[0.8125rem] text-faint">
            <tr role={cardMode ? 'row' : undefined}>
              {selection ? (
                <th
                  role={cardMode ? 'columnheader' : undefined}
                  data-mobile="select"
                  className={cn('pb-2', selection.headerClassName)}
                >
                  <Checkbox
                    aria-label={selection.all.label}
                    checked={selection.all.checked}
                    indeterminate={selection.all.indeterminate ?? false}
                    onChange={selection.all.onChange}
                    className={selection.all.checkboxClassName}
                  />
                </th>
              ) : null}
              {columns.map((column) => {
                const sortable = column.sortable === true && onSortChange !== undefined
                const active = sort?.columnId === columnSortKey(column)
                return (
                  <th
                    key={column.id}
                    role={cardMode ? 'columnheader' : undefined}
                    aria-sort={
                      sortable
                        ? active
                          ? sort?.direction === 'asc'
                            ? 'ascending'
                            : 'descending'
                          : 'none'
                        : undefined
                    }
                    className={cn('pb-2 font-medium', column.headerClassName)}
                  >
                    {sortable ? (
                      <button
                        type="button"
                        onClick={() => onSortChange(nextTableSort(sort, column))}
                        className="-mx-1 inline-flex items-center gap-1 rounded px-1 py-0.5 text-left hover:text-fg focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-muted"
                      >
                        {column.header}
                        <span
                          aria-hidden="true"
                          className={active ? 'text-fg' : 'opacity-50'}
                        >
                          {active ? (sort?.direction === 'asc' ? '↑' : '↓') : '↕'}
                        </span>
                      </button>
                    ) : (
                      column.header
                    )}
                  </th>
                )
              })}
            </tr>
          </thead>
          <tbody
            ref={bodyRef}
            role={cardMode ? 'rowgroup' : undefined}
            className="divide-y divide-border-subtle"
          >
            {ordered.map((row, index) => (
              <Fragment key={rowKey(row)}>
                {renderRow ? (
                  renderRow(row, index)
                ) : (
                  <DataTableRow
                    cardMode={cardMode}
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
                        data-empty={
                          column.cellEmpty?.(row) === true ? '' : undefined
                        }
                        {...mobileCellProps(column)}
                      >
                        <MobileCellLabel label={column.mobileLabel} />
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
    </>
  )
}

/** sortOptionLabel is a column's name in the mobile sort menu. */
function sortOptionLabel<T>(column: DataTableColumn<T>): string {
  if (column.sortLabel !== undefined) return column.sortLabel
  return typeof column.header === 'string' ? column.header : column.id
}

/** columnSortKey is the name a header reports: sortKey when set, id otherwise. */
function columnSortKey<T>(column: DataTableColumn<T>): string {
  return column.sortKey ?? column.id
}

/** nextTableSort flips an active column and starts a new one in its own direction. */
export function nextTableSort<T>(
  current: DataTableSort | undefined,
  column: DataTableColumn<T>,
): DataTableSort {
  const columnId = columnSortKey(column)
  if (current?.columnId === columnId) {
    return { columnId, direction: current.direction === 'asc' ? 'desc' : 'asc' }
  }
  return { columnId, direction: column.defaultSortDirection ?? 'asc' }
}

/**
 * sortTableRows orders rows in the browser by the active column's sortValue.
 * Numbers compare numerically and text case-insensitively, matching the
 * server's COLLATE NOCASE; a column without a comparator keeps the given order.
 */
export function sortTableRows<T>(
  rows: readonly T[],
  columns: readonly DataTableColumn<T>[],
  sort: DataTableSort,
): T[] {
  const column = columns.find(
    (candidate) => columnSortKey(candidate) === sort.columnId,
  )
  const value = column?.sortValue
  if (value === undefined) return [...rows]
  const direction = sort.direction === 'asc' ? 1 : -1
  return [...rows].sort(
    (left, right) => direction * compareSortValues(value(left), value(right)),
  )
}

/** compareSortValues orders two cell values; text ignores case. */
function compareSortValues(
  left: string | number,
  right: string | number,
): number {
  if (typeof left === 'number' && typeof right === 'number') {
    return left - right
  }
  const a = String(left).toLowerCase()
  const b = String(right).toLowerCase()
  if (a < b) return -1
  if (a > b) return 1
  return 0
}

/** useTableSort holds a table's sort state for tables sorted in the browser. */
export function useTableSort(defaultSort?: DataTableSort): {
  sort: DataTableSort | undefined
  onSortChange: (sort: DataTableSort) => void
} {
  const [sort, setSort] = useState<DataTableSort | undefined>(defaultSort)
  return { sort, onSortChange: setSort }
}

/** DataTableRow is the row shell, exported for callers that render rows themselves. */
export function DataTableRow({
  selection,
  onActivate,
  cardMode = false,
  children,
}: {
  selection?: DataTableRowSelection
  onActivate?: () => void
  /** Below md a row is a card; its role keeps the table semantics. */
  cardMode?: boolean
  children: ReactNode
}) {
  return (
    <tr
      role={cardMode ? 'row' : undefined}
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
      className={cn(
        'hover:bg-hover',
        onActivate
          ? 'cursor-pointer align-top focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-muted'
          : undefined,
      )}
    >
      {selection ? (
        // The checkbox cell must not open the row's detail view.
        <td
          role={cardMode ? 'cell' : undefined}
          data-mobile="select"
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
  // FindingsPage recreates these props every render; keep the effect keyed on
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
