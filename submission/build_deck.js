const pptx = require("pptxgenjs");
const p = new pptx();
p.defineLayout({ name: "W", width: 13.333, height: 7.5 });
p.layout = "W";

// ---- palette (ink / one blue accent / the ALLOW·ASK·DENY triad) ----
const BG="0B0E14", PANEL="121826", LINE="232C3D", LINE2="2E3A50";
const TEXT="EAEEF5", MUTE="9BA7BA", FAINT="5E6A7E";
const ACC="4C82F7", ALLOW="35D08A", ASK="F2B04A", DENY="F0645F", WHITE="FFFFFF";
const DISP="Arial", BODY="Calibri", MONO="Courier New";
const A="/Users/kavinsoorya/Documents/Agent-Guard/submission/assets/";
const ML=0.72, MR=12.61;

function bg(s){ s.background={color:BG}; }
function kicker(s,t){ s.addText(t.toUpperCase(),{x:ML,y:0.46,w:8,h:0.3,fontFace:DISP,fontSize:11,bold:true,color:ACC,charSpacing:2.5,align:"left",margin:0}); }
function foot(s,n){
  s.addText("AGENT GUARD",{x:ML,y:7.06,w:4,h:0.3,fontFace:MONO,fontSize:9,color:FAINT,charSpacing:1.5,align:"left",margin:0});
  s.addText(String(n).padStart(2,"0"),{x:MR-1,y:7.06,w:1,h:0.3,fontFace:MONO,fontSize:9,color:FAINT,align:"right",margin:0});
}
// three-state motif: small dot + label
function triad(s,x,y,scale=1){
  const items=[["ALLOW",ALLOW],["ASK",ASK],["DENY",DENY]]; let cx=x;
  items.forEach(([lab,c])=>{
    s.addShape(p.ShapeType.ellipse,{x:cx,y:y+0.02*scale,w:0.11*scale,h:0.11*scale,fill:{color:c},line:{type:"none"}});
    s.addText(lab,{x:cx+0.16*scale,y:y-0.06*scale,w:1.1*scale,h:0.3*scale,fontFace:MONO,fontSize:11*scale,bold:true,color:c,charSpacing:1,align:"left",margin:0});
    cx+=1.15*scale;
  });
}
function frame(s,path,x,y,w){ // framed screenshot with hairline + soft shadow
  const h=w/1.6222;
  s.addShape(p.ShapeType.rect,{x:x-0.03,y:y-0.03,w:w+0.06,h:h+0.06,fill:{color:PANEL},line:{color:LINE2,width:1}});
  s.addImage({path,x,y,w,h,shadow:{type:"outer",color:"000000",blur:14,offset:7,angle:90,opacity:0.45}});
  return h;
}
function box(s,x,y,w,h,fill){ s.addShape(p.ShapeType.rect,{x,y,w,h,fill:{color:fill||PANEL},line:{color:LINE,width:1}}); }
function arrowR(s,x,y,w){ s.addShape(p.ShapeType.line,{x,y,w,h:0,line:{color:LINE2,width:1.5,endArrowType:"triangle"}}); }
function arrowD(s,x,y,h){ s.addShape(p.ShapeType.line,{x,y,w:0,h,line:{color:LINE2,width:1.5,endArrowType:"triangle"}}); }

// ================================================================ 1 · COVER
(()=>{ const s=p.addSlide(); bg(s);
  s.addShape(p.ShapeType.roundRect,{x:ML,y:0.7,w:0.62,h:0.62,rectRadius:0.12,fill:{color:ACC},line:{type:"none"}});
  s.addText("AG",{x:ML,y:0.7,w:0.62,h:0.62,fontFace:DISP,fontSize:20,bold:true,color:WHITE,align:"center",valign:"middle",margin:0});
  s.addText("RUNTIME AGENT SECURITY",{x:ML+0.8,y:0.9,w:8,h:0.3,fontFace:DISP,fontSize:11,bold:true,color:MUTE,charSpacing:3,valign:"middle",margin:0});
  s.addText("Agent Guard",{x:ML-0.04,y:2.35,w:11,h:1.5,fontFace:DISP,fontSize:76,bold:true,color:WHITE,charSpacing:-1,align:"left",margin:0});
  s.addText([
    {text:"A runtime authorization firewall that evaluates ",options:{color:MUTE}},
    {text:"every autonomous-agent action",options:{color:TEXT,bold:true}},
    {text:" — against the user's goal, policy, and risk — ",options:{color:MUTE}},
    {text:"before it executes.",options:{color:TEXT,bold:true}},
  ],{x:ML,y:3.85,w:9.5,h:1.0,fontFace:BODY,fontSize:19,lineSpacingMultiple:1.15,align:"left",margin:0});
  s.addText("POST /guard/evaluate  →  ALLOW · ASK · DENY",{x:ML,y:5.55,w:9,h:0.3,fontFace:MONO,fontSize:12,color:ACC,margin:0});
  triad(s,ML,6.35,1.15);
  s.addText("Hackathon submission · v0.8",{x:MR-3,y:6.32,w:3,h:0.3,fontFace:MONO,fontSize:10,color:FAINT,align:"right",margin:0});
})();

// ================================================================ 2 · PROBLEM
(()=>{ const s=p.addSlide(); bg(s); kicker(s,"The problem"); foot(s,2);
  s.addText([
    {text:"Permission systems check ",options:{color:TEXT}},
    {text:"what",options:{color:ACC,italic:true}},
    {text:" a tool can touch —\nnot ",options:{color:TEXT}},
    {text:"whether",options:{color:ACC,italic:true}},
    {text:" the action still serves your goal.",options:{color:TEXT}},
  ],{x:ML,y:1.35,w:11.9,h:1.6,fontFace:DISP,fontSize:33,bold:true,lineSpacingMultiple:1.06,align:"left",margin:0});

  // concrete scenario, left = granted capability, right = the leak
  const y=3.75;
  s.addText("A CODING AGENT, ALREADY GRANTED FILESYSTEM ACCESS",{x:ML,y:y-0.55,w:11,h:0.3,fontFace:DISP,fontSize:12,bold:true,color:MUTE,charSpacing:2,margin:0});
  const steps=[
    ["GOAL","Build a React frontend. Don't touch secrets.",MUTE],
    ["ACTION","read  .env",TEXT],
    ["LEGACY AUTH","filesystem access granted  →  allowed  ✓",MUTE],
    ["RESULT","API keys read and exfiltrated",DENY],
  ];
  let cx=ML;
  const w=2.86, gap=(11.9-w*4)/3;
  steps.forEach(([lab,txt,c],i)=>{
    box(s,cx,y,w,1.55, i===3?"1B1114":PANEL);
    if(i===3) s.addShape(p.ShapeType.rect,{x:cx,y,w:w,h:1.55,fill:{type:"none"},line:{color:DENY,width:1.4}});
    s.addText(lab,{x:cx+0.22,y:y+0.2,w:w-0.4,h:0.3,fontFace:DISP,fontSize:10.5,bold:true,color:i===3?DENY:FAINT,charSpacing:1.5,margin:0});
    s.addText(txt,{x:cx+0.22,y:y+0.6,w:w-0.44,h:0.85,fontFace:(i===1?MONO:BODY),fontSize:i===1?15:13.5,bold:i===3,color:c,lineSpacingMultiple:1.05,valign:"top",margin:0});
    if(i<3) arrowR(s,cx+w+gap*0.12,y+0.77,gap*0.76);
    cx+=w+gap;
  });
  s.addText("The tool had permission. Nothing re-checked the action against the user's intent, at runtime, before it ran.",
    {x:ML,y:y+1.85,w:11.9,h:0.4,fontFace:BODY,fontSize:14,italic:true,color:MUTE,margin:0});
})();

// ================================================================ 3 · WHY NOW
(()=>{ const s=p.addSlide(); bg(s); kicker(s,"Why now"); foot(s,3);
  s.addText("One prompt now fans out into dozens of tool calls —\neach able to touch files, secrets, and the network.",
    {x:ML,y:1.35,w:11.9,h:1.4,fontFace:DISP,fontSize:31,bold:true,color:TEXT,lineSpacingMultiple:1.07,margin:0});

  // fan-out: prompt -> agent -> 5 tool chips  (shifted below the headline)
  const chipH=0.62, cgap=0.22, bx=ML+4.95, bw=1.44, y0=3.05;
  const startX=ML+4.45;                       // agent box right edge
  const colBot=y0+5*chipH+4*cgap, agentCy=(y0+colBot)/2;
  box(s,ML,agentCy-0.43,2.0,0.86,PANEL);
  s.addText("User prompt",{x:ML,y:agentCy-0.43,w:2.0,h:0.86,fontFace:BODY,fontSize:13,bold:true,color:TEXT,align:"center",valign:"middle",margin:0});
  box(s,ML+2.55,agentCy-0.43,1.9,0.86,PANEL);
  s.addText("AI agent",{x:ML+2.55,y:agentCy-0.43,w:1.9,h:0.86,fontFace:BODY,fontSize:13,bold:true,color:TEXT,align:"center",valign:"middle",margin:0});
  arrowR(s,ML+2.02,agentCy,0.5);
  const chips=[["read","file"],["write","file"],["delete","file"],["run","command"],["http","request"]];
  chips.forEach(([a,b],i)=>{
    const yy=y0+i*(chipH+cgap);
    s.addShape(p.ShapeType.line,{x:startX,y:agentCy,w:bx-startX,h:(yy+chipH/2)-agentCy,line:{color:LINE2,width:1.2,endArrowType:"triangle"}});
    box(s,bx,yy,bw,chipH,PANEL);
    s.addText(a,{x:bx,y:yy+0.08,w:bw,h:0.26,fontFace:MONO,fontSize:12.5,bold:true,color:ACC,align:"center",margin:0});
    s.addText(b,{x:bx,y:yy+0.34,w:bw,h:0.22,fontFace:MONO,fontSize:10,color:FAINT,align:"center",margin:0});
  });
  // right note (starts below the headline)
  const nx=bx+bw+0.6;
  s.addText("Autonomous · multi-step · no human in the loop",{x:nx,y:3.25,w:4.2,h:0.4,fontFace:DISP,fontSize:12.5,bold:true,color:MUTE,charSpacing:0.5,margin:0});
  s.addText([
    {text:"Traditional auth grants a capability ",options:{color:MUTE}},
    {text:"once",options:{color:TEXT,bold:true}},
    {text:".\nNothing re-evaluates each individual action at the moment it runs — where goal drift, secret access, and exfiltration actually happen.",options:{color:MUTE}},
  ],{x:nx,y:3.85,w:4.2,h:2,fontFace:BODY,fontSize:14,lineSpacingMultiple:1.18,margin:0});
})();

// ================================================================ 4 · SOLUTION (hero)
(()=>{ const s=p.addSlide(); bg(s); kicker(s,"The solution"); foot(s,4);
  s.addText("Agent Guard sits between the agent and its tools —\nand rules on every proposed action before it executes.",
    {x:ML,y:1.3,w:11.9,h:1.1,fontFace:DISP,fontSize:26,bold:true,color:TEXT,lineSpacingMultiple:1.06,margin:0});
  // left copy
  s.addText([
    {text:"ALLOW",options:{color:ALLOW,bold:true}},{text:"  relevant, in-scope, low risk → runs.\n",options:{color:MUTE}},
    {text:"ASK",options:{color:ASK,bold:true}},{text:"      sensitive or destructive → a human decides.\n",options:{color:MUTE}},
    {text:"DENY",options:{color:DENY,bold:true}},{text:"    secret, out-of-scope, exfiltration → blocked.",options:{color:MUTE}},
  ],{x:ML,y:2.95,w:4.6,h:1.6,fontFace:MONO,fontSize:14,lineSpacingMultiple:1.5,margin:0});
  s.addText("Every decision carries a risk score, an explainable reason, and a redacted audit record.",
    {x:ML,y:5.15,w:4.55,h:1.0,fontFace:BODY,fontSize:14,italic:true,color:MUTE,lineSpacingMultiple:1.2,margin:0});
  // hero
  frame(s,A+"dashboard.png",5.75,2.55,6.85);
  s.addText("Live runtime monitor — a real Antigravity MCP session, every call evaluated.",
    {x:5.75,y:6.85,w:6.85,h:0.3,fontFace:MONO,fontSize:9.5,color:FAINT,align:"left",margin:0});
})();

// ================================================================ 5 · HOW IT WORKS
(()=>{ const s=p.addSlide(); bg(s); kicker(s,"How it works"); foot(s,5);
  s.addText("Every tool call is intercepted, evaluated, and executed only if authorized.",
    {x:ML,y:1.3,w:11.9,h:0.7,fontFace:DISP,fontSize:26,bold:true,color:TEXT,margin:0});

  // top row: Agent -> MCP/SDK -> /guard/evaluate
  const ry=2.5, bh=0.9;
  const n=(x,w,t,sub,mono)=>{ box(s,x,ry,w,bh,PANEL);
    s.addText(t,{x,y:ry+0.15,w,h:0.3,fontFace:mono?MONO:BODY,fontSize:13.5,bold:true,color:TEXT,align:"center",margin:0});
    if(sub) s.addText(sub,{x,y:ry+0.5,w,h:0.3,fontFace:MONO,fontSize:10,color:FAINT,align:"center",margin:0}); };
  n(ML,2.5,"AI Agent","Antigravity · Claude Code");
  arrowR(s,ML+2.5,ry+bh/2,0.5);
  n(ML+3.0,2.7,"MCP server / SDK","GuardedExecutor");
  arrowR(s,ML+5.7,ry+bh/2,0.5);
  n(ML+6.2,3.0,"POST /guard/evaluate","action + goal + payload",true);
  s.addText("intercept BEFORE execution",{x:ML+6.2,y:ry-0.36,w:3.0,h:0.3,fontFace:DISP,fontSize:9.5,bold:true,color:ACC,charSpacing:1,align:"center",margin:0});

  // engine block (big, center)
  const ey=4.05, ew=8.3, eh=2.05;
  box(s,ML,ey,ew,eh,"0E1522");
  s.addShape(p.ShapeType.rect,{x:ML,y:ey,w:ew,h:eh,fill:{type:"none"},line:{color:ACC,width:1.3}});
  s.addText("SECURITY ENGINE",{x:ML+0.28,y:ey+0.2,w:5,h:0.3,fontFace:DISP,fontSize:11,bold:true,color:ACC,charSpacing:2,margin:0});
  s.addText("1 · DETERMINISTIC GATES  — the authority",{x:ML+0.28,y:ey+0.6,w:7.8,h:0.3,fontFace:DISP,fontSize:12,bold:true,color:TEXT,charSpacing:0.5,margin:0});
  const gates=["secret_exfil","protected_resource","policy_scope","destructive","external_comm"];
  let gx=ML+0.28; gates.forEach(g=>{ const w=1.5;
    box(s,gx,ey+0.98,w,0.42,PANEL);
    s.addText(g,{x:gx,y:ey+0.98,w,h:0.42,fontFace:MONO,fontSize:9.5,color:MUTE,align:"center",valign:"middle",margin:0}); gx+=w+0.08; });
  s.addText([
    {text:"2 · GOAL-AWARE LLM ADVISOR ",options:{color:TEXT,bold:true}},
    {text:" — advisory only: may escalate ALLOW→ASK, never override a DENY",options:{color:MUTE}},
  ],{x:ML+0.28,y:ey+1.55,w:7.9,h:0.3,fontFace:BODY,fontSize:12,margin:0});

  // decision + downstream (right)
  arrowR(s,ML+ew,ey+eh/2,0.42);
  const dx=ML+ew+0.85;
  s.addShape(p.ShapeType.rect,{x:dx,y:ey+0.05,w:2.75,h:0.62,fill:{color:"101a12"},line:{color:ALLOW,width:1.2}});
  s.addText([{text:"ALLOW ",options:{color:ALLOW,bold:true}},{text:"· ASK ",options:{color:ASK,bold:true}},{text:"· DENY",options:{color:DENY,bold:true}}],
    {x:dx,y:ey+0.05,w:2.75,h:0.62,fontFace:MONO,fontSize:13,align:"center",valign:"middle",margin:0});
  arrowD(s,dx+1.37,ey+0.7,0.35);
  box(s,dx,ey+1.1,2.75,0.42,PANEL);
  s.addText("Execute if authorized",{x:dx,y:ey+1.1,w:2.75,h:0.42,fontFace:BODY,fontSize:11,bold:true,color:TEXT,align:"center",valign:"middle",margin:0});
  arrowD(s,dx+1.37,ey+1.55,0.2);
  box(s,dx,ey+1.78,2.75,0.42,PANEL);
  s.addText("Audit + approval (redacted)",{x:dx,y:ey+1.78,w:2.75,h:0.42,fontFace:BODY,fontSize:10.5,color:MUTE,align:"center",valign:"middle",margin:0});
})();

// ================================================================ 6 · INNOVATION 1
(()=>{ const s=p.addSlide(); bg(s); kicker(s,"Core innovation · 1"); foot(s,6);
  s.addText("The LLM advises. Deterministic gates decide.",
    {x:ML,y:1.3,w:11.9,h:0.7,fontFace:DISP,fontSize:33,bold:true,color:TEXT,margin:0});
  s.addText("Most \"AI security\" asks a model for a verdict. A model can be wrong, prompt-injected, or unavailable. Agent Guard never lets it be the boundary.",
    {x:ML,y:2.15,w:11.6,h:0.7,fontFace:BODY,fontSize:15,color:MUTE,lineSpacingMultiple:1.2,margin:0});

  const y=3.3, cw=5.75, gap=0.4;
  // deterministic lane — full accent border marks the authority
  box(s,ML,y,cw,3.05,"0E1522");
  s.addShape(p.ShapeType.rect,{x:ML,y,w:cw,h:3.05,fill:{type:"none"},line:{color:ACC,width:1.2}});
  s.addText("DETERMINISTIC GATES",{x:ML+0.3,y:y+0.28,w:cw-0.6,h:0.3,fontFace:DISP,fontSize:13,bold:true,color:ACC,charSpacing:1.5,margin:0});
  s.addText("Authoritative",{x:ML+0.3,y:y+0.62,w:cw-0.6,h:0.3,fontFace:BODY,fontSize:12,italic:true,color:MUTE,margin:0});
  ["Glob-matched protected files (.env, keys, creds)","Goal-scope + destructive-action rules","Secret / PII / financial detection (regex + entropy, Luhn, Verhoeff)","Exfiltration: sensitive data + external destination"].forEach((t,i)=>{
    s.addText([{text:"— ",options:{color:ACC,bold:true}},{text:t,options:{color:TEXT}}],
      {x:ML+0.3,y:y+1.05+i*0.46,w:cw-0.55,h:0.44,fontFace:BODY,fontSize:12.5,lineSpacingMultiple:1.0,valign:"top",margin:0});
  });
  // advisory lane
  const x2=ML+cw+gap;
  box(s,x2,y,cw,3.05,PANEL);
  s.addText("GOAL-AWARE LLM ADVISOR",{x:x2+0.3,y:y+0.28,w:cw-0.6,h:0.3,fontFace:DISP,fontSize:13,bold:true,color:MUTE,charSpacing:1.5,margin:0});
  s.addText("Advisory",{x:x2+0.3,y:y+0.62,w:cw-0.6,h:0.3,fontFace:BODY,fontSize:12,italic:true,color:FAINT,margin:0});
  ["Rates goal↔action relevance; flags goal drift","May escalate a borderline ALLOW → ASK","Can NEVER turn a DENY into ALLOW","Receives categories only — never the raw payload or secret"].forEach((t,i)=>{
    const c = i>=2?ACC:MUTE;
    s.addText([{text:"— ",options:{color:FAINT,bold:true}},{text:t,options:{color:i>=2?TEXT:MUTE,bold:i>=2}}],
      {x:x2+0.3,y:y+1.05+i*0.46,w:cw-0.55,h:0.44,fontFace:BODY,fontSize:12.5,valign:"top",margin:0});
  });
  s.addText("final = max-severity( deterministic , advisory )   —   a hard DENY is final.",
    {x:ML,y:y+3.25,w:11.9,h:0.35,fontFace:MONO,fontSize:13,color:ACC,align:"center",margin:0});
})();

// ================================================================ 7 · INNOVATION 2 (fingerprint)
(()=>{ const s=p.addSlide(); bg(s); kicker(s,"Core innovation · 2"); foot(s,7);
  s.addText("An approval is bound to the exact action — it can't be reused for another.",
    {x:ML,y:1.3,w:11.9,h:1.1,fontFace:DISP,fontSize:29,bold:true,color:TEXT,lineSpacingMultiple:1.05,margin:0});
  s.addText([
    {text:"fingerprint = SHA-256( goal + policy + operation + resource + destination + payload-hash + context )",options:{}},
  ],{x:ML,y:2.5,w:11.9,h:0.35,fontFace:MONO,fontSize:12.5,color:ACC,margin:0});

  const y=3.35, cw=5.75, gap=0.4;
  // defense
  box(s,ML,y,cw,3.0,"101a12");
  s.addShape(p.ShapeType.rect,{x:ML,y,w:cw,h:3.0,fill:{type:"none"},line:{color:ALLOW,width:1.2}});
  s.addText("HUMAN APPROVES  ·  ASK",{x:ML+0.3,y:y+0.25,w:cw-0.6,h:0.3,fontFace:DISP,fontSize:12,bold:true,color:ALLOW,charSpacing:1.5,margin:0});
  s.addText("delete  src/generated.jsx",{x:ML+0.3,y:y+0.72,w:cw-0.6,h:0.35,fontFace:MONO,fontSize:15,bold:true,color:TEXT,margin:0});
  s.addText("→ fingerprint  af_9c31…8b0c",{x:ML+0.3,y:y+1.2,w:cw-0.6,h:0.3,fontFace:MONO,fontSize:12,color:MUTE,margin:0});
  s.addText("→ APPROVED, bound to this fingerprint",{x:ML+0.3,y:y+1.62,w:cw-0.6,h:0.3,fontFace:MONO,fontSize:12,color:MUTE,margin:0});
  s.addText("Consume with the SAME action → re-verified → executes exactly once.",
    {x:ML+0.3,y:y+2.2,w:cw-0.6,h:0.7,fontFace:BODY,fontSize:13,color:TEXT,lineSpacingMultiple:1.15,margin:0});
  // attack
  const x2=ML+cw+gap;
  box(s,x2,y,cw,3.0,"1B1114");
  s.addShape(p.ShapeType.rect,{x:x2,y,w:cw,h:3.0,fill:{type:"none"},line:{color:DENY,width:1.2}});
  s.addText("ATTACKER REUSES THE APPROVAL",{x:x2+0.3,y:y+0.25,w:cw-0.6,h:0.3,fontFace:DISP,fontSize:12,bold:true,color:DENY,charSpacing:1.2,margin:0});
  s.addText("delete  database.sql",{x:x2+0.3,y:y+0.72,w:cw-0.6,h:0.35,fontFace:MONO,fontSize:15,bold:true,color:TEXT,margin:0});
  s.addText("→ fingerprint  af_5f0a…d19e",{x:x2+0.3,y:y+1.2,w:cw-0.6,h:0.3,fontFace:MONO,fontSize:12,color:MUTE,margin:0});
  s.addText("→ MISMATCH — the approval does not apply",{x:x2+0.3,y:y+1.62,w:cw-0.6,h:0.3,fontFace:MONO,fontSize:12,color:DENY,bold:true,margin:0});
  s.addText([{text:"BLOCKED",options:{color:DENY,bold:true}},{text:"  — the tool is never called. Same defense stops replay, expiry, and post-approval edits.",options:{color:TEXT}}],
    {x:x2+0.3,y:y+2.2,w:cw-0.6,h:0.7,fontFace:BODY,fontSize:13,lineSpacingMultiple:1.15,margin:0});
})();

// ================================================================ 8 · PRODUCTION
(()=>{ const s=p.addSlide(); bg(s); kicker(s,"Production implementation"); foot(s,8);
  s.addText("This is a built system, not a slide — verified end-to-end.",
    {x:ML,y:1.3,w:11.9,h:0.7,fontFace:DISP,fontSize:30,bold:true,color:TEXT,margin:0});

  // metric column (left)
  const stats=[["205","automated tests passing (189 backend · 16 frontend)"],
               ["5","deterministic security gates, authoritative"],
               ["8","guarded MCP tools exposed to the IDE"]];
  let y=2.55;
  stats.forEach(([n,l])=>{
    s.addText(n,{x:ML,y,w:2.1,h:0.9,fontFace:DISP,fontSize:46,bold:true,color:WHITE,align:"left",margin:0});
    s.addText(l,{x:ML+2.25,y:y+0.14,w:3.7,h:0.7,fontFace:BODY,fontSize:13,color:MUTE,lineSpacingMultiple:1.12,valign:"middle",margin:0});
    y+=1.18;
  });

  // capability list (right) — real modules, terse, not carded
  const rx=ML+6.5;
  s.addShape(p.ShapeType.line,{x:rx-0.45,y:2.55,w:0,h:3.35,line:{color:LINE,width:1}});
  s.addText("SHIPPED MODULES",{x:rx,y:2.5,w:5,h:0.3,fontFace:DISP,fontSize:11,bold:true,color:ACC,charSpacing:2,margin:0});
  const mods=[
    ["Pure decision engine","gates · risk scoring · goal compiler"],
    ["FastAPI service","auth · rate limit · security headers · fail-closed"],
    ["Agent SDK","GuardedExecutor enforces the verdict"],
    ["MCP server","real Antigravity IDE integration over stdio"],
    ["Modular detectors","secrets · PII (Verhoeff) · financial (Luhn)"],
    ["React dashboard + Docker","one-command deploy, persistent audit"],
  ];
  let my=2.95;
  mods.forEach(([t,d])=>{
    s.addText([{text:t,options:{color:TEXT,bold:true}},{text:"   "+d,options:{color:FAINT}}],
      {x:rx,y:my,w:5.7,h:0.4,fontFace:BODY,fontSize:13,margin:0,valign:"top"});
    my+=0.485;
  });
})();

// ================================================================ 9 · METRICS
(()=>{ const s=p.addSlide(); bg(s); kicker(s,"Security · performance · scale"); foot(s,9);
  s.addText("Sub-millisecond decisions. Zero secret leakage. Fail-closed by design.",
    {x:ML,y:1.3,w:11.9,h:0.7,fontFace:DISP,fontSize:28,bold:true,color:TEXT,margin:0});

  const cards=[
    ["0.10","ms","p95 decision latency","deterministic engine, offline advisor"],
    ["21,700","/s","evaluations per second","single thread, n = 20,000"],
    ["0","raw","secrets in response, audit, or DB","only redacted fingerprints persist"],
  ];
  const y=2.75, w=3.7, gap=(11.9-w*3)/2; let x=ML;
  cards.forEach(([big,unit,l1,l2])=>{
    box(s,x,y,w,2.15,PANEL);
    s.addText([{text:big,options:{fontSize:52,color:WHITE,bold:true}},{text:" "+unit,options:{fontSize:20,color:ACC,bold:true}}],
      {x:x+0.3,y:y+0.35,w:w-0.6,h:0.95,fontFace:DISP,align:"left",valign:"middle",margin:0});
    s.addText(l1,{x:x+0.3,y:y+1.35,w:w-0.6,h:0.32,fontFace:BODY,fontSize:14,bold:true,color:TEXT,margin:0});
    s.addText(l2,{x:x+0.3,y:y+1.68,w:w-0.6,h:0.32,fontFace:MONO,fontSize:10.5,color:FAINT,margin:0});
    x+=w+gap;
  });

  // scalability line
  s.addText("SCALES BECAUSE",{x:ML,y:5.35,w:4,h:0.3,fontFace:DISP,fontSize:11,bold:true,color:ACC,charSpacing:2,margin:0});
  const pts=[
    ["Stateless engine","pure functions; horizontally scalable behind the API"],
    ["Pluggable stores","AuditStore / ApprovalStore interfaces — SQLite → Postgres"],
    ["Fail-closed","any error, timeout, or malformed response → block, never allow"],
  ];
  let px=ML;
  const pw=(11.9-0.8)/3;
  pts.forEach(([t,d])=>{
    s.addText(t,{x:px,y:5.75,w:pw,h:0.3,fontFace:BODY,fontSize:13.5,bold:true,color:TEXT,margin:0});
    s.addText(d,{x:px,y:6.08,w:pw,h:0.7,fontFace:BODY,fontSize:12,color:MUTE,lineSpacingMultiple:1.12,valign:"top",margin:0});
    px+=pw+0.4;
  });
})();

// ================================================================ 10 · MCP hero
(()=>{ const s=p.addSlide(); bg(s); kicker(s,"Real IDE integration"); foot(s,10);
  s.addText("Wired into a real IDE: Antigravity's tool calls flow through Agent Guard over MCP.",
    {x:ML,y:1.3,w:6.15,h:2.0,fontFace:DISP,fontSize:24,bold:true,color:TEXT,lineSpacingMultiple:1.08,margin:0});
  s.addText([
    {text:"Every ",options:{color:MUTE}},{text:"read / write / delete / command / network",options:{color:TEXT,bold:true}},
    {text:" call the agent makes is evaluated first.",options:{color:MUTE}},
  ],{x:ML,y:3.05,w:4.9,h:0.9,fontFace:BODY,fontSize:14.5,lineSpacingMultiple:1.2,margin:0});
  const rows=[
    ["Stable session","reconnects update the same session — no stale duplicates"],
    ["guarded_read_files","batches safe reads into one call — fewer IDE prompts"],
    ["Individually evaluated",".env inside a batch is still DENIED"],
    ["Honest boundary","guards tools routed through it — no silent interception"],
  ];
  let ry=4.05;
  rows.forEach(([t,d])=>{
    s.addShape(p.ShapeType.ellipse,{x:ML,y:ry+0.06,w:0.1,h:0.1,fill:{color:ACC},line:{type:"none"}});
    s.addText([{text:t+"  ",options:{color:TEXT,bold:true}},{text:d,options:{color:FAINT}}],
      {x:ML+0.24,y:ry-0.05,w:4.9,h:0.55,fontFace:BODY,fontSize:12.5,lineSpacingMultiple:1.05,valign:"top",margin:0});
    ry+=0.66;
  });
  frame(s,A+"integration.png",7.3,2.3,5.3);
  s.addText("Connected-agent registry, live — real Antigravity session over MCP.",
    {x:7.3,y:5.68,w:5.3,h:0.3,fontFace:MONO,fontSize:9.5,color:FAINT,margin:0});
})();

// ================================================================ 11 · USE CASES
(()=>{ const s=p.addSlide(); bg(s); kicker(s,"Where it belongs"); foot(s,11);
  s.addText("A policy decision point for any agent that touches real systems.",
    {x:ML,y:1.3,w:11.9,h:0.7,fontFace:DISP,fontSize:28,bold:true,color:TEXT,margin:0});
  const uc=[
    ["01","Coding agents in the IDE","Antigravity, Claude Code and similar agents edit files, run commands, and hit the network mid-task. Agent Guard stops secret reads, destructive edits, and exfiltration the moment they're proposed — without slowing safe work."],
    ["02","Autonomous tool-using agents & platforms","Any framework where an LLM drives file, shell, database, and HTTP tools gains one place to enforce goal-scoped policy — via the SDK or a direct /guard/evaluate call."],
    ["03","Enterprise AI governance","A redacted, fingerprint-bound, auditable record of every agent action — with human approval on high-impact operations — turns agent autonomy into something a security team can sign off on."],
  ];
  let y=2.55;
  uc.forEach(([num,t,d])=>{
    s.addText(num,{x:ML,y:y-0.06,w:1.0,h:0.7,fontFace:DISP,fontSize:30,bold:true,color:LINE2,margin:0});
    s.addText(t,{x:ML+1.15,y:y-0.04,w:10.4,h:0.4,fontFace:DISP,fontSize:17,bold:true,color:TEXT,margin:0});
    s.addText(d,{x:ML+1.15,y:y+0.4,w:10.6,h:0.9,fontFace:BODY,fontSize:13.5,color:MUTE,lineSpacingMultiple:1.16,valign:"top",margin:0});
    s.addShape(p.ShapeType.line,{x:ML,y:y+1.42,w:11.9,h:0,line:{color:LINE,width:1}});
    y+=1.55;
  });
})();

// ================================================================ 12 · CLOSE
(()=>{ const s=p.addSlide(); bg(s);
  s.addShape(p.ShapeType.roundRect,{x:ML,y:0.7,w:0.5,h:0.5,rectRadius:0.1,fill:{color:ACC},line:{type:"none"}});
  s.addText("AG",{x:ML,y:0.7,w:0.5,h:0.5,fontFace:DISP,fontSize:15,bold:true,color:WHITE,align:"center",valign:"middle",margin:0});
  s.addText([
    {text:"AI agents need ",options:{color:MUTE}},
    {text:"runtime, goal-aware authorization",options:{color:WHITE,bold:true}},
    {text:" —\nnot just permission to use a tool.",options:{color:MUTE}},
  ],{x:ML,y:2.55,w:11.6,h:1.8,fontFace:DISP,fontSize:40,bold:true,lineSpacingMultiple:1.08,margin:0});
  s.addText("Agent Guard makes every action prove it belongs — before it runs.",
    {x:ML,y:4.8,w:11,h:0.5,fontFace:BODY,fontSize:18,italic:true,color:MUTE,margin:0});
  triad(s,ML,5.7,1.2);
  s.addText("github.com/Kavin-ks/Agent-Guard",{x:MR-4.5,y:5.72,w:4.5,h:0.3,fontFace:MONO,fontSize:11,color:FAINT,align:"right",margin:0});
})();

p.writeFile({ fileName: "/Users/kavinsoorya/Documents/Agent-Guard/Agent_Guard_Pitch.pptx" })
 .then(f=>console.log("WROTE", f));
