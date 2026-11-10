/**
 * A small Markdown renderer for the guides in `docs/`, so the dashboard shows the same
 * text people read on GitHub. It knows what those guides use and no more: headings,
 * paragraphs, lists (with paragraphs and code inside an item), tables, block quotes,
 * fenced code, and inline code, bold and links. Everything is escaped; raw HTML in the
 * source is shown as text.
 */

import { escape, Html } from "./html.js";

const LINK_OK = /^(https?:\/\/|\/|#)/;

function inline(text: string): string {
  // Code spans are set aside first, so bold and links can wrap them and never reach inside.
  const code: string[] = [];
  const held = text.replace(/`([^`]+)`/g, (_w, c: string) => `\u0000${code.push(`<code>${escape(c)}</code>`) - 1}\u0000`);
  return escape(held)
    .replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>")
    .replace(/\[([^\]]+)\]\(([^)\s]+)\)/g, (whole, label: string, url: string) =>
      LINK_OK.test(url) ? `<a href="${url}"${url.startsWith("http") ? ' target="_blank" rel="noopener noreferrer"' : ""}>${label}</a>` : whole)
    .replace(/\u0000(\d+)\u0000/g, (_w, n: string) => code[Number(n)]);
}

const LIST_ITEM = /^(\s*)([-*]|\d+\.)\s+(.*)$/;
const HEADING = /^(#{1,4})\s+(.*)$/;
const TABLE_RULE = /^\s*\|?\s*:?-{3,}:?\s*(\|\s*:?-{3,}:?\s*)*\|?\s*$/;
const cells = (line: string) => line.trim().replace(/^\||\|$/g, "").split("|").map((c) => c.trim());
const slug = (s: string) => s.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");

function blocks(lines: string[]): string {
  const out: string[] = [];
  let i = 0;
  const startsBlock = (l: string) => HEADING.test(l) || LIST_ITEM.test(l) || l.startsWith("```") || l.startsWith(">") || l.trim().startsWith("|") || /^-{3,}\s*$/.test(l);

  while (i < lines.length) {
    const line = lines[i];
    if (!line.trim()) {
      i++;
      continue;
    }
    if (line.startsWith("```")) {
      const code: string[] = [];
      for (i++; i < lines.length && !lines[i].startsWith("```"); i++) code.push(lines[i]);
      i++;
      out.push(`<pre><code>${escape(code.join("\n"))}</code></pre>`);
      continue;
    }
    const h = HEADING.exec(line);
    if (h) {
      out.push(`<h${h[1].length} id="${slug(h[2])}">${inline(h[2])}</h${h[1].length}>`);
      i++;
      continue;
    }
    if (/^-{3,}\s*$/.test(line)) {
      out.push("<hr>");
      i++;
      continue;
    }
    if (line.startsWith(">")) {
      const quoted: string[] = [];
      for (; i < lines.length && lines[i].startsWith(">"); i++) quoted.push(lines[i].replace(/^>\s?/, ""));
      out.push(`<blockquote>${blocks(quoted)}</blockquote>`);
      continue;
    }
    if (line.trim().startsWith("|") && i + 1 < lines.length && TABLE_RULE.test(lines[i + 1])) {
      const head = cells(line);
      const rows: string[][] = [];
      for (i += 2; i < lines.length && lines[i].trim().startsWith("|"); i++) rows.push(cells(lines[i]));
      out.push(`<div class="scroll"><table><tr>${head.map((c) => `<th>${inline(c)}</th>`).join("")}</tr>${rows
        .map((r) => `<tr>${r.map((c) => `<td>${inline(c)}</td>`).join("")}</tr>`).join("")}</table></div>`);
      continue;
    }
    const first = LIST_ITEM.exec(line);
    if (first) {
      const ordered = /\d/.test(first[2]);
      const indent = first[1].length;
      const items: string[] = [];
      while (i < lines.length) {
        const m = LIST_ITEM.exec(lines[i]);
        if (!m || m[1].length !== indent || /\d/.test(m[2]) !== ordered) break;
        const width = indent + m[2].length + 1;
        const body = [m[3]];
        for (i++; i < lines.length; i++) {
          const l = lines[i];
          if (!l.trim()) {
            // A blank line stays in the item only if what follows is indented under it.
            const next = lines.slice(i + 1).find((x) => x.trim());
            if (next === undefined || next.length - next.trimStart().length < width) break;
            body.push("");
          } else if (l.length - l.trimStart().length >= width) {
            body.push(l.slice(width));
          } else {
            break;
          }
        }
        const inner = blocks(body);
        const single = /^<p>([\s\S]*)<\/p>$/.exec(inner);
        items.push(`<li>${single && !single[1].includes("<p>") ? single[1] : inner}</li>`);
        while (i < lines.length && !lines[i].trim()) i++;
      }
      out.push(`<${ordered ? "ol" : "ul"}>${items.join("")}</${ordered ? "ol" : "ul"}>`);
      continue;
    }
    const para: string[] = [];
    for (; i < lines.length && lines[i].trim() && !(para.length && startsBlock(lines[i])); i++) para.push(lines[i].trim());
    out.push(`<p>${inline(para.join(" "))}</p>`);
  }
  return out.join("\n");
}

export function markdown(source: string): Html {
  return new Html(blocks(source.replace(/\r\n?/g, "\n").split("\n")));
}
