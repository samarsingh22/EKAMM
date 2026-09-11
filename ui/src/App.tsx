import { Route, Routes } from "react-router-dom";

import Shell from "./components/layout/Shell";
import Overview from "./pages/Overview";
import Events from "./pages/Events";
import Sources from "./pages/Sources";
import Templates from "./pages/Templates";
import Integrity from "./pages/Integrity";
import Anomalies from "./pages/Anomalies";
import DeadLetters from "./pages/DeadLetters";

export default function App() {
  return (
    <Shell>
      <Routes>
        {/* `/console` is the Overview in dev, where `/` serves the landing page
            (see vite.config.ts); `/` still works for the built dashboard. */}
        <Route path="/" element={<Overview />} />
        <Route path="/console" element={<Overview />} />
        <Route path="/events" element={<Events />} />
        <Route path="/events/:eventUid" element={<Events />} />
        <Route path="/sources" element={<Sources />} />
        <Route path="/templates" element={<Templates />} />
        <Route path="/integrity" element={<Integrity />} />
        <Route path="/anomalies" element={<Anomalies />} />
        <Route path="/dlq" element={<DeadLetters />} />
      </Routes>
    </Shell>
  );
}
