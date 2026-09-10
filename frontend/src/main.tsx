import React,{useEffect,useMemo,useState} from 'react';
import {createRoot} from 'react-dom/client';
import {Activity,Pause,Play,RefreshCw,Search,Download,Database,Radio} from 'lucide-react';
import './style.css';

type Packet={id:string;received_at:string;router_ip:string;src_ip?:string;dst_ip?:string;protocol?:string;src_port?:number;dst_port?:number;length:number;info?:string};
const API='/api';
function auth(){const t=localStorage.getItem('routershark_token')||'';return t?{Authorization:`Bearer ${t}`}:{}}
function App(){
 const [packets,setPackets]=useState<Packet[]>([]),[selected,setSelected]=useState<Packet|null>(null),[decoded,setDecoded]=useState<any>(null),[hex,setHex]=useState(''),[paused,setPaused]=useState(false),[filter,setFilter]=useState(''),[search,setSearch]=useState(''),[status,setStatus]=useState('connecting');
 const load=async()=>{const r=await fetch(`${API}/packets?limit=500&q=${encodeURIComponent(search)}`,{headers:auth()});if(r.ok)setPackets(await r.json())};
 useEffect(()=>{load();const token=localStorage.getItem('routershark_token')||'';const proto=location.protocol==='https:'?'wss':'ws';const ws=new WebSocket(`${proto}://${location.host}/ws/packets${token?`?token=${encodeURIComponent(token)}`:''}`);ws.onopen=()=>setStatus('live');ws.onclose=()=>setStatus('offline');ws.onmessage=e=>{if(paused)return;const p=JSON.parse(e.data);setPackets(v=>[p,...v].slice(0,1000))};return()=>ws.close()},[paused]);
 const inspect=async(p:Packet)=>{setSelected(p);setDecoded(null);setHex('');const [d,h]=await Promise.all([fetch(`${API}/packets/${p.id}/decode`,{headers:auth()}),fetch(`${API}/packets/${p.id}/hex`,{headers:auth()})]);if(d.ok)setDecoded(await d.json());if(h.ok)setHex((await h.json()).hex)};
 const protoStats=useMemo(()=>{const m=new Map<string,number>();for(const p of packets)m.set(p.protocol||'OTHER',(m.get(p.protocol||'OTHER')||0)+1);return [...m.entries()].sort((a,b)=>b[1]-a[1]).slice(0,8)},[packets]);
 const applyDisplayFilter=async()=>{if(!filter){load();return} const to=new Date(),from=new Date(to.getTime()-5*60_000);const r=await fetch(`${API}/display-filter?filter=${encodeURIComponent(filter)}&from=${encodeURIComponent(from.toISOString())}&to=${encodeURIComponent(to.toISOString())}&limit=10000`,{headers:auth()});if(!r.ok){alert(await r.text());return}const x=await r.json();setPackets(x.packets||[]);setPaused(true)};
 return <div className="app">
  <header><div className="brand"><Radio size={23}/><b>RouterShark</b><span>Web Packet Analyzer</span></div><div className={`pill ${status}`}>{status}</div></header>
  <div className="toolbar"><button onClick={()=>setPaused(!paused)}>{paused?<Play size={16}/>:<Pause size={16}/>} {paused?'Continuar':'Pausar'}</button><button onClick={load}><RefreshCw size={16}/>Atualizar</button><button onClick={()=>{const t=localStorage.getItem('routershark_token')||'';location.href=`${API}/export.pcap?from=${encodeURIComponent(new Date(Date.now()-5*60_000).toISOString())}&to=${encodeURIComponent(new Date().toISOString())}&limit=20000${t?`&token=${encodeURIComponent(t)}`:''}`}}><Download size={16}/>PCAP</button><div className="filter"><Search size={16}/><input value={filter} onChange={e=>setFilter(e.target.value)} onKeyDown={e=>e.key==='Enter'&&applyDisplayFilter()} placeholder="Display filter: tcp.port == 443 && ip.addr == 10.0.0.1"/><button onClick={applyDisplayFilter}>Aplicar</button></div></div>
  <section className="stats"><div><Activity/><strong>{packets.length}</strong><small>pacotes na tela</small></div><div><Database/><strong>{packets.reduce((a,p)=>a+p.length,0).toLocaleString()}</strong><small>bytes na tela</small></div>{protoStats.slice(0,4).map(([p,n])=><div key={p}><strong>{p}</strong><span>{n}</span><small>quadros</small></div>)}</section>
  <main>
   <div className="packetpane"><div className="subbar"><input value={search} onChange={e=>setSearch(e.target.value)} onKeyDown={e=>e.key==='Enter'&&load()} placeholder="Pesquisar IP, info..."/></div><table><thead><tr><th>No.</th><th>Time</th><th>Router</th><th>Source</th><th>Destination</th><th>Proto</th><th>Len</th><th>Info</th></tr></thead><tbody>{packets.map((p,i)=><tr key={p.id} onClick={()=>inspect(p)} className={selected?.id===p.id?'sel':''}><td>{i+1}</td><td>{new Date(p.received_at).toLocaleTimeString()}</td><td>{p.router_ip}</td><td>{p.src_ip||'—'}{p.src_port?`:${p.src_port}`:''}</td><td>{p.dst_ip||'—'}{p.dst_port?`:${p.dst_port}`:''}</td><td><span className={`proto p-${p.protocol}`}>{p.protocol||'OTHER'}</span></td><td>{p.length}</td><td>{p.info}</td></tr>)}</tbody></table></div>
   <div className="details"><div className="tabs"><b>Packet Details</b><span>{selected?.id||'Selecione um pacote'}</span></div><pre className="decode">{decoded?JSON.stringify(decoded,null,2):'Clique em um pacote para decodificação completa pelo TShark.'}</pre><div className="tabs"><b>Packet Bytes</b></div><pre className="hex">{hex||'—'}</pre></div>
  </main>
 </div>
}
createRoot(document.getElementById('root')!).render(<App/>);
