import { describe, expect, it } from 'vitest'

import { parseBlocks, parseSpans } from './markdown'

describe('parseBlocks', () => {
  it('splits advisory text into headings, paragraphs, lists and code', () => {
    const source = [
      '## HTTP/2 Rapid reset attack',
      'The protocol allows',
      'cancellation.',
      '',
      '- one',
      '- two',
      '  continued',
      '```',
      '<script>x</script>',
      '```',
    ].join('\n')
    expect(parseBlocks(source)).toEqual([
      { kind: 'heading', text: 'HTTP/2 Rapid reset attack' },
      { kind: 'paragraph', text: 'The protocol allows cancellation.' },
      { kind: 'list', items: ['one', 'two continued'] },
      { kind: 'code', text: '<script>x</script>' },
    ])
  })
})

describe('parseSpans', () => {
  it('keeps only https links and marks code and bold', () => {
    expect(
      parseSpans('Use `Channel` **now** [a](https://x.io) [b](javascript:alert(1))'),
    ).toEqual([
      { kind: 'text', text: 'Use ' },
      { kind: 'code', text: 'Channel' },
      { kind: 'text', text: ' ' },
      { kind: 'bold', text: 'now' },
      { kind: 'text', text: ' ' },
      { kind: 'link', text: 'a', href: 'https://x.io' },
      { kind: 'text', text: ' [b](javascript:alert(1))' },
    ])
  })
})
