import { parseBlocks, parseSpans } from '../lib/markdown'

function Inline({ text }: { text: string }) {
  return (
    <>
      {parseSpans(text).map((span, index) => {
        const key = String(index)
        switch (span.kind) {
          case 'code':
            return (
              <code key={key} className="rounded bg-bg px-1 font-mono text-[0.75rem] text-fg">
                {span.text}
              </code>
            )
          case 'bold':
            return (
              <strong key={key} className="font-semibold text-fg">
                {span.text}
              </strong>
            )
          case 'link':
            return (
              <a
                key={key}
                href={span.href}
                target="_blank"
                rel="noreferrer noopener"
                className="underline underline-offset-2 hover:text-fg"
              >
                {span.text}
              </a>
            )
          default:
            return span.text
        }
      })}
    </>
  )
}

/** MarkdownText renders untrusted Markdown as plain React elements (§4.3). */
export function MarkdownText({ source }: { source: string }) {
  return (
    <div className="flex flex-col gap-2 text-[0.8125rem] leading-relaxed break-words text-muted">
      {parseBlocks(source).map((block, index) => {
        const key = String(index)
        switch (block.kind) {
          case 'heading':
            return (
              <h4 key={key} className="pt-1 text-[0.8125rem] font-semibold text-fg">
                <Inline text={block.text} />
              </h4>
            )
          case 'list':
            return (
              <ul key={key} className="flex list-disc flex-col gap-1 pl-5">
                {block.items.map((item, i) => (
                  <li key={String(i)}>
                    <Inline text={item} />
                  </li>
                ))}
              </ul>
            )
          case 'code':
            return (
              <pre
                key={key}
                className="overflow-x-auto rounded-md bg-bg p-2 font-mono text-[0.75rem] text-fg"
              >
                {block.text}
              </pre>
            )
          default:
            return (
              <p key={key}>
                <Inline text={block.text} />
              </p>
            )
        }
      })}
    </div>
  )
}
