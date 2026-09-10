const WILDCARD_RE = /<[^>]+>/g;

/** Renders a mined template string with its `<WILDCARD>` tokens styled distinctly from literal text. */
export default function TemplateText({ template, className }: { template: string; className?: string }) {
  const parts = template.split(WILDCARD_RE);
  const wildcards = template.match(WILDCARD_RE) ?? [];

  return (
    <span className={`font-mono text-xs ${className ?? ""}`}>
      {parts.map((literal, i) => (
        <span key={i}>
          <span className="text-text">{literal}</span>
          {wildcards[i] && (
            <span className="rounded bg-accent-bg px-1 py-0.5 font-semibold text-accent">{wildcards[i]}</span>
          )}
        </span>
      ))}
    </span>
  );
}
