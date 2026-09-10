import type { PropsWithChildren } from "react";

import Sidebar from "./Sidebar";
import TopBar from "./TopBar";

/** The app frame: sidebar + top bar, with routed page content scrolling underneath. */
export default function Shell({ children }: PropsWithChildren) {
  return (
    <div className="flex h-screen w-screen overflow-hidden bg-bg text-text">
      <Sidebar />
      <div className="flex min-w-0 flex-1 flex-col">
        <TopBar />
        <main className="flex-1 overflow-y-auto p-6">{children}</main>
      </div>
    </div>
  );
}
