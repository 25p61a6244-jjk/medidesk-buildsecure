(function(){
  const launcher=document.getElementById('aiLauncher'), panel=document.getElementById('aiPanel'), close=document.getElementById('aiClose'), form=document.getElementById('aiForm'), input=document.getElementById('aiInput'), messages=document.getElementById('aiMessages');
  if(!launcher||!panel) return;
  function openAI(){panel.classList.add('open');panel.setAttribute('aria-hidden','false');setTimeout(()=>input&&input.focus(),80)}
  function closeAI(){panel.classList.remove('open');panel.setAttribute('aria-hidden','true')}
  launcher.addEventListener('click',openAI); close&&close.addEventListener('click',closeAI);
  document.querySelectorAll('[data-ai]').forEach(b=>b.addEventListener('click',()=>send(b.dataset.ai)));
  function bubble(text,who){const d=document.createElement('div');d.className='ai-msg '+who;d.textContent=text;messages.appendChild(d);messages.scrollTop=messages.scrollHeight;return d}
  async function send(text){text=(text||'').trim();if(!text)return; bubble(text,'user'); if(input)input.value=''; const typing=bubble('Thinking…','bot');typing.classList.add('ai-typing');try{const token=document.querySelector('meta[name="csrf-token"]')?.content;const r=await fetch('/ai',{method:'POST',headers:{'Content-Type':'application/json','X-CSRFToken':token||''},body:JSON.stringify({message:text})});const data=await r.json();typing.remove();bubble(data.answer||'I could not answer that right now.','bot')}catch(e){typing.remove();bubble('MediDesk AI is temporarily unavailable. You can use Help & FAQ or Contact Support.','bot')}}
  form&&form.addEventListener('submit',e=>{e.preventDefault();send(input.value)});
})();
