import type { LucideIcon } from "lucide-react";

interface PagePlaceholderProps {
  title: string;
  description: string;
  icon: LucideIcon;
}

/** Stand-in for a not-yet-built page — keeps routing/shell verifiable ahead of real content. */
export default function PagePlaceholder({ title, description, icon: Icon }: PagePlaceholderProps) {
  return (
    <div className="flex h-full min-h-[60vh] flex-col items-center justify-center gap-3 rounded-lg border border-dashed border-border text-center">
      <Icon className="h-8 w-8 text-text-faint" strokeWidth={1.5} />
      <h2 className="text-lg font-medium text-text">{title}</h2>
      <p className="max-w-sm text-sm text-text-muted">{description}</p>
    </div>
  );
}
