import paper from "./assets/paper.jpg";
import { Analyzer } from "./components/Analyzer";
import { Hero, PolicyMatrix, SiteFooter, SiteHeader, Source, Transcript } from "./components/Sections";

export default function App() {
  return (
    <div className="grain relative min-h-screen bg-paper text-ink">
      {/* fixed stock texture — sits under the content so type stays crisp */}
      <div
        aria-hidden
        className="pointer-events-none fixed inset-0 z-0 opacity-45 mix-blend-multiply"
        style={{
          backgroundImage: `url(${paper})`,
          backgroundSize: "cover",
          backgroundPosition: "center",
        }}
      />
      <div className="relative z-10">
        <SiteHeader />
        <main>
          <Hero />
          <Analyzer />
          <Transcript />
          <PolicyMatrix />
          <Source />
        </main>
        <SiteFooter />
      </div>
    </div>
  );
}
