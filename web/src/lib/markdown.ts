/**
 * A deliberately small Markdown reader for scanner advisory text (§4.3: the
 * text is untrusted). It only splits text into blocks and inline spans; the
 * caller renders them as React elements, so nothing becomes raw HTML.
 * ponytail: headings, lists, fences, `code`, **bold** and [links](https://…)
 * cover advisory text; tables and nesting are shown as plain text.
 */

export type Block =
  | { kind: 'heading'; text: string }
  | { kind: 'paragraph'; text: string }
  | { kind: 'list'; items: string[] }
  | { kind: 'code'; text: string }

export type Span =
  | { kind: 'text'; text: string }
  | { kind: 'code'; text: string }
  | { kind: 'bold'; text: string }
  | { kind: 'link'; text: string; href: string }

const listItem = /^\s*(?:[-*+]|\d+[.)])\s+(.*)$/

export function parseBlocks(source: string): Block[] {
  const blocks: Block[] = []
  let paragraph: string[] = []
  let list: string[] | null = null
  let code: string[] | null = null

  const flush = () => {
    if (paragraph.length) blocks.push({ kind: 'paragraph', text: paragraph.join(' ') })
    if (list) blocks.push({ kind: 'list', items: list })
    paragraph = []
    list = null
  }

  for (const line of source.replace(/\r\n?/g, '\n').split('\n')) {
    if (code) {
      if (line.trimStart().startsWith('```')) {
        blocks.push({ kind: 'code', text: code.join('\n') })
        code = null
      } else code.push(line)
      continue
    }
    if (line.trimStart().startsWith('```')) {
      flush()
      code = []
      continue
    }
    const heading = /^\s*#{1,6}\s+(.*)$/.exec(line)
    if (heading) {
      flush()
      blocks.push({ kind: 'heading', text: heading[1].trim() })
      continue
    }
    const item = listItem.exec(line)
    if (item) {
      if (paragraph.length) flush()
      list ??= []
      list.push(item[1].trim())
      continue
    }
    if (line.trim() === '') {
      flush()
      continue
    }
    if (list && /^\s+/.test(line)) {
      list[list.length - 1] += ` ${line.trim()}`
      continue
    }
    if (list) flush()
    paragraph.push(line.trim())
  }
  if (code) blocks.push({ kind: 'code', text: code.join('\n') })
  flush()
  return blocks
}

const inline = /(`[^`]+`|\*\*[^*]+\*\*|\[[^\]]+\]\(https:\/\/[^)\s]+\))/

export function parseSpans(text: string): Span[] {
  return text
    .split(inline)
    .filter((part) => part !== '')
    .map((part): Span => {
      if (part.startsWith('`') && part.endsWith('`') && part.length > 2)
        return { kind: 'code', text: part.slice(1, -1) }
      if (part.startsWith('**') && part.endsWith('**') && part.length > 4)
        return { kind: 'bold', text: part.slice(2, -2) }
      const link = /^\[([^\]]+)\]\((https:\/\/[^)\s]+)\)$/.exec(part)
      if (link) return { kind: 'link', text: link[1], href: link[2] }
      return { kind: 'text', text: part }
    })
}
