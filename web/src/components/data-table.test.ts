import { describe, expect, it } from 'vitest'

import {
  nextTableSort,
  sortTableRows,
  type DataTableColumn,
} from './data-table'

type Row = { name: string; count: number }

const columns: DataTableColumn<Row>[] = [
  { id: 'name', header: 'Name', sortable: true, sortValue: (row) => row.name },
  { id: 'count', header: 'Count', sortable: true, sortValue: (row) => row.count },
  { id: 'plain', header: 'Plain' },
]

const rows: Row[] = [
  { name: 'beta', count: 2 },
  { name: 'Alpha', count: 10 },
  { name: 'gamma', count: 1 },
]

describe('sortTableRows', () => {
  it('orders numbers ascending and descending', () => {
    expect(
      sortTableRows(rows, columns, { columnId: 'count', direction: 'asc' }).map(
        (row) => row.count,
      ),
    ).toEqual([1, 2, 10])
    expect(
      sortTableRows(rows, columns, { columnId: 'count', direction: 'desc' }).map(
        (row) => row.count,
      ),
    ).toEqual([10, 2, 1])
  })

  it('orders text without regard to case, like the server', () => {
    expect(
      sortTableRows(rows, columns, { columnId: 'name', direction: 'asc' }).map(
        (row) => row.name,
      ),
    ).toEqual(['Alpha', 'beta', 'gamma'])
  })

  it('keeps the given order for a column without a comparator', () => {
    expect(
      sortTableRows(rows, columns, { columnId: 'plain', direction: 'asc' }),
    ).toEqual(rows)
  })
})

describe('nextTableSort', () => {
  it('starts a new column in its own direction', () => {
    const severity: DataTableColumn<Row> = {
      id: 'severity',
      header: 'Severity',
      sortable: true,
      defaultSortDirection: 'desc',
    }
    expect(nextTableSort(undefined, severity)).toEqual({
      columnId: 'severity',
      direction: 'desc',
    })
  })

  it('flips the active column and reports sortKey when set', () => {
    const title: DataTableColumn<Row> = {
      id: 'finding',
      header: 'Finding',
      sortable: true,
      sortKey: 'title',
    }
    expect(nextTableSort(undefined, title)).toEqual({
      columnId: 'title',
      direction: 'asc',
    })
    expect(
      nextTableSort({ columnId: 'title', direction: 'asc' }, title),
    ).toEqual({ columnId: 'title', direction: 'desc' })
  })
})
