(function(){
  if(document.getElementById("tl-panel")) return;

  const panel = document.createElement("div");
  panel.id = "tl-panel";
  panel.innerHTML = `
    <div id="tl-header">
      <strong>Tailored Learning</strong>
      <button id="tl-close">✕</button>
    </div>
    <div id="tl-body">
      <div class="vmg-card"><b>Status:</b> 
        Ready. Select an email and click “Analyze”.</div>
      <button id="tl-analyze">Analyze current email</button>
      <div id="tl-result" class="tl-card"></div>
    </div>
    <div id="tl-input">
      <input id="vmg-q" placeholder="Ask AI (local)…"/>
      <button id="tl-send">Send</button>
    </div>`;
  document.documentElement.appendChild(panel);

  panel.querySelector("#tl-close").onclick = () => panel.remove();

  async function getSelectionText(){
    // minimal fallback: grab selected text on page (works anywhere)
    return String(window.getSelection());
  }

  async function analyze(body){
    try {
      const res = await fetch("http://localhost:8000/analyze-email/",{
        method:"POST",
        headers:{ "Content-Type":"application/json" },
        body: JSON.stringify({ sender:"unknown@web", subject:
            "(web selection)", body })
      });
      if(!res.ok) throw new Error("Server error");
      return await res.json();
    } catch(e){
      // mock fallback
      const urls = (body.match(/https?:\/\/\S+/g)||[]);
      const flagged = ["urgent","verify","password","click here",
        "update account"].filter(k=>body.toLowerCase().includes(k));
      const score = Math.min(100, flagged.length*20 + urls.length*10);
      return { analysis: { subject:"(web selection)", sender:"unknown@web", 
        body, urls, flagged_keywords:flagged, risk_score:score, verdict: 
        score>=60?"Phishing":score>=30?"Suspicious":"Legitimate" }};
    }
  }

  panel.querySelector("#tl-analyze").onclick = async ()=>{
    const text = await getSelectionText();
    const data = await analyze(text);
    panel.querySelector("#tl-result").innerHTML =
      `<div><b>Verdict:</b> ${data.analysis.verdict} — Risk 
            ${data.analysis.risk_score}</div>
       <div><b>URLs:</b> ${(data.analysis.urls||[]).join(", ")||"none"}</div>
       <div><b>Flags:</b> ${(data.analysis.flagged_keywords||[]).join(", ")
        ||"none"}</div>`;
  };

  panel.querySelector("#tl-send").onclick = ()=>{
    const q = panel.querySelector("#tl-q").value.trim();
    if(!q) return;
    // later: call local LLM endpoint
    alert("AI (mock): Look for sender mismatch, urgent tone, and login links.");
    panel.querySelector("#tl-q").value = "";
  };
})();
