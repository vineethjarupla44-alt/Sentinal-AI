/**
 * TraceGuard - Toast Notification Service
 * Renders sleek frosted floating notifications matching Stitch aesthetic
 */

let toastContainer = null;

function ensureToastContainer() {
  if (!toastContainer) {
    toastContainer = document.createElement('div');
    toastContainer.className = 'toast-container';
    document.body.appendChild(toastContainer);
  }
}

export function showToast(message, type = 'info', duration = 3200) {
  ensureToastContainer();

  const toast = document.createElement('div');
  toast.className = `toast-item toast-${type} animate-fade-in`;

  const iconSvg = type === 'success' 
    ? `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#34D399" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>`
    : type === 'warning'
    ? `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#FF8A48" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>`
    : `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#58D7E8" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>`;

  toast.innerHTML = `
    <div class="toast-icon">${iconSvg}</div>
    <div class="toast-message">${message}</div>
  `;

  toastContainer.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateY(-10px) scale(0.95)';
    toast.style.transition = 'all 0.3s ease';
    setTimeout(() => {
      if (toast.parentNode) toast.parentNode.removeChild(toast);
    }, 300);
  }, duration);
}
