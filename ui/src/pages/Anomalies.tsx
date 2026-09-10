import { useState } from "react";

import { useAnomaliesList, useAnomalyDrift, useAnomalyModel, useAnomalyTimeline } from "../api/hooks";
import AnomalyScoreChart from "../components/anomalies/AnomalyScoreChart";
import DriftPanel from "../components/anomalies/DriftPanel";
import FlaggedTable from "../components/anomalies/FlaggedTable";
import ModelInfoCard from "../components/anomalies/ModelInfoCard";

const TIMELINE_WINDOWS = ["15m", "1h", "6h", "24h"] as const;

/** Bucket width paired to each look-back window so the chart stays ~30–60 points wide. */
function bucketFor(window: string): string {
  switch (window) {
    case "15m":
      return "30s";
    case "6h":
      return "10m";
    case "24h":
      return "1h";
    default:
      return "2m";
  }
}

export default function Anomalies() {
  const [timelineWindow, setTimelineWindow] = useState<string>("1h");
  const [driftWindowMin, setDriftWindowMin] = useState<number>(5);

  const modelQuery = useAnomalyModel(true);
  const timelineQuery = useAnomalyTimeline(timelineWindow, bucketFor(timelineWindow), true);
  const flaggedQuery = useAnomaliesList({ limit: 200 }, true);
  const driftQuery = useAnomalyDrift(driftWindowMin, 3, true);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-lg font-semibold text-text">Anomalies</h1>
        <p className="text-sm text-text-faint">
          Isolation-Forest scoring over the OCSF feature matrix, every alert explained by the
          features that drove it — plus template-rate drift straight from the log parser.
        </p>
      </div>

      <ModelInfoCard info={modelQuery.data} loading={modelQuery.isLoading} />

      <AnomalyScoreChart
        data={timelineQuery.data}
        loading={timelineQuery.isLoading}
        window={timelineWindow}
        windows={TIMELINE_WINDOWS}
        onWindowChange={setTimelineWindow}
      />

      <FlaggedTable rows={flaggedQuery.data} loading={flaggedQuery.isLoading} />

      <DriftPanel
        signals={driftQuery.data}
        loading={driftQuery.isLoading}
        windowMinutes={driftWindowMin}
        onWindowChange={setDriftWindowMin}
      />
    </div>
  );
}
