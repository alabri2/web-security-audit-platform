const form = document.getElementById('scanForm');
const resultCard = document.getElementById('resultCard');
const statusInfo = document.getElementById('statusInfo');
const findingsList = document.getElementById('findingsList');
const reportLink = document.getElementById('reportLink');
const pdfReportLink = document.getElementById('pdfReportLink');
const targetMode = document.getElementById('targetMode');
const manualTypeWrapper = document.getElementById('manualTypeWrapper');

document.getElementById('clearBtn').addEventListener('click', () => {
  form.reset();
  manualTypeWrapper.style.display = 'none';
  findingsList.innerHTML = '';
  findingsList.style.display = 'none';
});

targetMode.addEventListener('change', () => {
  manualTypeWrapper.style.display = targetMode.value === 'manual' ? 'block' : 'none';
});

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, (m) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;'
  }[m]));
}

function getSecurityLevel(score){
  if(score >= 90) return {label:"Excellent", color:"#16a34a"};
  if(score >= 75) return {label:"Good", color:"#22c55e"};
  if(score >= 50) return {label:"Medium", color:"#f59e0b"};
  if(score >= 25) return {label:"Poor", color:"#f97316"};
  return {label:"Critical", color:"#ef4444"};
}

function updateScoreCircle(score){
  const circle = document.getElementById("scoreCircle");
  const value = document.getElementById("scoreValue");
  const label = document.getElementById("scoreLabel");
  const result = getSecurityLevel(score);
  circle.style.setProperty("--score", score);
  circle.style.setProperty("--color", result.color);
  value.textContent = score + "%";
  label.textContent = result.label;
}

form.addEventListener('submit', async (e) => {
  e.preventDefault();

  const url = document.getElementById('url').value.trim();
  const mode = document.getElementById('mode').value;
  const selectedTargetMode = document.getElementById('targetMode').value;
  const selectedTargetType = document.getElementById('targetType').value;
  const authorized = document.getElementById('authorized').checked;

  if(!authorized){
    alert("Tu dois confirmer que tu es autorisé à scanner cette cible.");
    return;
  }

  const payload = {
    url,
    mode,
    target_mode: selectedTargetMode,
    target_type: selectedTargetMode === 'manual' ? selectedTargetType : null,
    authorized
  };

  const res = await fetch('/api/webscan', {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify(payload)
  });

  const data = await res.json();
  if(!res.ok){
    alert(data.detail || "Erreur lors du lancement du scan.");
    return;
  }

  resultCard.style.display = 'block';
  statusInfo.innerHTML = `<p><strong>ID:</strong> ${escapeHtml(data.scan_id)}</p><p><strong>Statut:</strong> queued</p>`;
  updateScoreCircle(0);

  findingsList.innerHTML = '';
  findingsList.style.display = 'none';

  reportLink.style.display = 'none';
  pdfReportLink.style.display = 'none';
  poll(data.scan_id);
});

async function poll(scanId){
  const timer = setInterval(async () => {
    const res = await fetch(`/api/webscan/${scanId}`);
    if(!res.ok) return;
    const data = await res.json();

    statusInfo.innerHTML = `
      <p><strong>ID:</strong> ${escapeHtml(data.id)}</p>
      <p><strong>Statut:</strong> ${escapeHtml(data.status)}</p>
      <p><strong>Score:</strong> ${data.score ?? '-'}</p>
      <p><strong>Niveau:</strong> ${escapeHtml(data.security_level ?? '-')}</p>
      <p><strong>Cible:</strong> ${escapeHtml(data.target)}</p>
      <p><strong>Mode:</strong> ${escapeHtml(data.mode)}</p>
      <p><strong>Type final:</strong> ${escapeHtml((data.extra && data.extra.target_type) ? data.extra.target_type : '-')}</p>
      <p><strong>Sélection du type:</strong> ${escapeHtml((data.extra && data.extra.selection_mode) ? data.extra.selection_mode : '-')}</p>
      <p><strong>Autorisation:</strong> ${(data.extra && data.extra.authorization_confirmed) ? 'confirmée' : 'non confirmée'}</p>`;

    updateScoreCircle(data.score || 0);

    findingsList.innerHTML = '';
    findingsList.style.display = 'none';

    if(data.status === 'finished' || data.status === 'failed'){
      clearInterval(timer);
      reportLink.href = `/api/webscan/${scanId}/report`;
      pdfReportLink.href = `/api/webscan/${scanId}/report/pdf`;
      reportLink.style.display = 'inline-block';
      pdfReportLink.style.display = 'inline-block';
    }
  }, 3000);
}
