// Enhanced radar with motion, audio, and modes
const canvas = document.createElement('canvas');
canvas.width = window.innerWidth;
canvas.height = window.innerHeight;
document.getElementById('radar-container').appendChild(canvas);
const ctx = canvas.getContext('2d');

// Mode variables
let nightVision = false;
let tacticalMode = false;

// Audio for alerts
const alertSound = new Audio('/static/audio/alert.wav'); // Assume audio file exists or use Web Audio API

// Device history for motion trails
const deviceHistory = new Map();

// Animation variables
let animationTime = 0;

function drawRadar(devices) {
  // Clear canvas with mode-specific background
  if (nightVision) {
    ctx.fillStyle = 'rgba(0, 20, 0, 0.9)'; // Green phosphor base
  } else {
    ctx.fillStyle = 'rgba(0,0,0,0.2)';
  }
  ctx.fillRect(0, 0, canvas.width, canvas.height);

  const cx = canvas.width / 2;
  const cy = canvas.height / 2;
  const maxR = Math.min(cx, cy) * 0.9;

  // Draw rings with enhanced style
  ctx.strokeStyle = nightVision ? '#0f0' : '#050';
  ctx.lineWidth = tacticalMode ? 2 : 1;
  for (let r = 50; r <= maxR; r += 50) {
    ctx.beginPath();
    ctx.arc(cx, cy, r, 0, Math.PI * 2);
    ctx.stroke();
    // Add range labels in tactical mode
    if (tacticalMode) {
      ctx.fillStyle = '#0f0';
      ctx.font = '12px monospace';
      ctx.fillText(`${r}m`, cx + r + 5, cy);
    }
  }

  // Draw crosshairs in tactical mode
  if (tacticalMode) {
    ctx.strokeStyle = '#0f0';
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.moveTo(cx - 20, cy);
    ctx.lineTo(cx + 20, cy);
    ctx.moveTo(cx, cy - 20);
    ctx.lineTo(cx, cy + 20);
    ctx.stroke();
  }

  // Draw blips with trails and animations
  devices.forEach((d, i) => {
    if (d.error) return;
    const angle = (i * 37) % 360;
    const dist = Math.min(d.distance || 10, 100) / 100;
    const x = cx + Math.cos(angle * Math.PI / 180) * dist * maxR;
    const y = cy + Math.sin(angle * Math.PI / 180) * dist * maxR;

    // Update history for trails
    if (!deviceHistory.has(d.mac)) {
      deviceHistory.set(d.mac, []);
    }
    const history = deviceHistory.get(d.mac);
    history.push({x, y, time: Date.now()});
    if (history.length > 10) history.shift(); // Keep last 10 positions

    // Draw motion trails
    ctx.strokeStyle = '#0f0';
    ctx.lineWidth = 1;
    ctx.globalAlpha = 0.5;
    for (let j = 1; j < history.length; j++) {
      const prev = history[j-1];
      const curr = history[j];
      const age = (Date.now() - prev.time) / 1000;
      ctx.globalAlpha = Math.max(0.1, 1 - age);
      ctx.beginPath();
      ctx.moveTo(prev.x, prev.y);
      ctx.lineTo(curr.x, curr.y);
      ctx.stroke();
    }
    ctx.globalAlpha = 1;

    let color = '#0f0';
    let radius = 6;
    let pulsing = false;
    if (d.privacy_risk >= 4) {
      color = '#f00';
      pulsing = true;
      // Audio alert for new high-risk devices
      if (!d.alerted) {
        alertSound.play().catch(() => {}); // Ignore errors if audio fails
        d.alerted = true;
      }
    } else if (d.privacy_risk >= 3) {
      color = '#ff0';
    }

    // Pulsing animation
    if (pulsing) {
      const pulse = Math.sin(animationTime * 0.01) * 0.5 + 0.5;
      radius = 6 + pulse * 4;
      ctx.globalAlpha = 0.5 + pulse * 0.5;
    }

    ctx.fillStyle = color;
    ctx.beginPath();
    ctx.arc(x, y, radius, 0, Math.PI * 2);
    ctx.fill();
    ctx.globalAlpha = 1;

    ctx.fillStyle = '#0af';
    ctx.font = '12px monospace';
    ctx.fillText(d.name || d.mac, x + 10, y);
  });

  // Night vision overlay
  if (nightVision) {
    ctx.fillStyle = 'rgba(0, 255, 0, 0.1)';
    ctx.fillRect(0, 0, canvas.width, canvas.height);
  }

  animationTime++;
  requestAnimationFrame(() => drawRadar(devices)); // Continuous animation
}

// Live update via polling
setInterval(() => {
  fetch('/api/devices')
    .then(r => r.json())
    .then(devices => {
      // Reset alerted flag for new scans
      devices.forEach(d => d.alerted = false);
      drawRadar(devices);
    });
}, 3000);

// Mode toggle functions
function toggleNightVision() {
  nightVision = !nightVision;
  document.body.classList.toggle('night-vision', nightVision);
  document.getElementById('night-vision-btn').classList.toggle('active', nightVision);
}

function toggleTactical() {
  tacticalMode = !tacticalMode;
  document.body.classList.toggle('tactical', tacticalMode);
  document.getElementById('tactical-btn').classList.toggle('active', tacticalMode);
}

// Initial draw
drawRadar([]);