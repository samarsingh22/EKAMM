import { ActivitySquare } from "lucide-react";

import PagePlaceholder from "../components/PagePlaceholder";

export default function Anomalies() {
  return (
    <PagePlaceholder
      title="Anomalies"
      description="Template frequency drift — each template's current-window rate vs. its baseline, with a z-score."
      icon={ActivitySquare}
    />
  );
}
