// app shell

import {Routes, Route, Link } from "react-router-dom";
import Dashboard from "./pages/dashboard";
import Analyze from "./pages/analyze";
import EmailDetail from "./pages/emailDetail";
import Settings from "./pages/settings"; 
import ChatDock from "./components/chatDock"; 
import ModeToggle from "./components/modeToggle";



export default function App(){
  return (
    <>
       <header style={{ display: "flex", gap: 12, alignItems: "center", padding: 12 }}>
        <Link to="/" style={{ fontWeight: 700, textDecoration: "none" }}>🕴️ Tailored Learning</Link>
        <nav style={{ display: "flex", gap: 12, marginLeft: 16 }}>
          <Link to="/" className="navlink">Dashboard</Link>
          <Link to="/analyze" className="navlink">Analyze</Link>
          <Link to="/settings" className="navlink">Settings</Link>
        </nav>
        <div style={{ marginLeft: "auto" }}>
          <ModeToggle />
        </div>
      </header>

      <main style={{display:"grid",gridTemplateColumns:"1fr 360px",gap:16,padding:16}}>
        <section className="panel">
          <Routes>
            <Route path="/" element={<Dashboard/>}/>
            <Route path="/analyze" element={<Analyze/>}/>
            <Route path="/email/:id" element={<EmailDetail/>}/>
            <Route path="/settings" element={<Settings/>}/>
          </Routes>
        </section>
        <aside className="panel">
          <ChatDock/>
        </aside>
      </main>
    </>
  );
}