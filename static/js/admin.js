// admin.js - Admin Dashboard & User Management
// Clean, deduplicated, CSRF-safe, Dark Mode enabled

(function () {
  'use strict';

  // --- UTILITY: Show Alert Pop-up ---
  function showAlert(type, message) {
    let alert = document.querySelector('.admin-alert');
    if (!alert) {
      alert = document.createElement('div');
      alert.className = 'admin-alert';
      document.body.appendChild(alert);
    }
    alert.className = `admin-alert alert-${type}`;
    alert.innerHTML = `
      <i class="fas fa-${type === 'success' ? 'check-circle' : 'exclamation-circle'}"></i>
      <div class="alert-message">${message}</div>
      <button class="close" onclick="this.parentElement.remove()">×</button>
    `;
    setTimeout(() => alert.remove(), 6000);
  }

  // --- UTILITY: Copy to Clipboard ---
  function copyToClipboard(elementId) {
    const text = document.getElementById(elementId).textContent;
    navigator.clipboard.writeText(text).then(() => {
      const btn = event.target;
      const original = btn.innerHTML;
      btn.innerHTML = 'Copied!';
      btn.disabled = true;
      setTimeout(() => {
        btn.innerHTML = original;
        btn.disabled = false;
      }, 1500);
    });
  }

  // --- MODAL: Open / Close ---
  function openCreateModal() {
    document.getElementById('createModal').style.display = 'flex';
  }
  function closeCreateModal() {
    document.getElementById('createModal').style.display = 'none';
    document.getElementById('createForm').reset();
  }
  function openDeleteModal(id, name) {
    document.getElementById('deleteId').value = id;
    document.getElementById('deleteName').textContent = name;
    document.getElementById('deleteModal').style.display = 'flex';
  }
  function closeDeleteModal() {
    document.getElementById('deleteModal').style.display = 'none';
    document.getElementById('deleteForm').reset();
  }

  // Close modals on background click
  document.querySelectorAll('.modal').forEach(modal => {
    modal.addEventListener('click', function (e) {
      if (e.target === this) {
        this.style.display = 'none';
        if (this.id === 'createModal') closeCreateModal();
        if (this.id === 'deleteModal') closeDeleteModal();
      }
    });
  });

  // --- CREATE USER: Submit Form ---
  const createForm = document.getElementById('createForm');
  if (createForm) {
    createForm.onsubmit = function (e) {
      e.preventDefault();
      const form = this;
      const data = new FormData(form);
      const submitBtn = form.querySelector('button[type="submit"]');
      const originalText = submitBtn.innerHTML;

      submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Creating...';
      submitBtn.disabled = true;

      fetch('/create_user', {
        method: 'POST',
        body: data
      })
        .then(r => r.json())
        .then(resp => {
          if (resp.success) {
            const msg = `
              User Created!<br><br>
              <strong>Staff #:</strong> ${resp.staff_number}<br>
              <strong>Password:</strong> <code id="tempPass">${resp.temp_password}</code>
              <button onclick="copyToClipboard('tempPass')" class="btn btn-sm btn-secondary" style="margin-left:8px;padding:2px 8px;font-size:0.8rem;">
                Copy
              </button>
              <br><small>They must change it on first login.</small>
            `;
            showAlert('success', msg);
            closeCreateModal();
            setTimeout(() => location.reload(), 3000);
          } else {
            showAlert('error', resp.message || 'Failed to create user');
          }
        })
        .catch(err => {
          console.error(err);
          showAlert('error', 'Network error');
        })
        .finally(() => {
          submitBtn.innerHTML = originalText;
          submitBtn.disabled = false;
        });
    };
  }

  // --- DELETE USER: Submit Form ---
  const deleteForm = document.getElementById('deleteForm');
  if (deleteForm) {
    deleteForm.onsubmit = function (e) {
      e.preventDefault();
      const form = this;
      const data = new FormData(form);
      const submitBtn = form.querySelector('button[type="submit"]');
      const originalText = submitBtn.innerHTML;

      submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Deleting...';
      submitBtn.disabled = true;

      fetch('/delete_user', {
        method: 'POST',
        body: data
      })
        .then(r => r.json())
        .then(resp => {
          showAlert(resp.success ? 'success' : 'error', resp.message);
          if (resp.success) {
            closeDeleteModal();
            setTimeout(() => location.reload(), 1000);
          }
        })
        .catch(err => {
          console.error(err);
          showAlert('error', 'Network error');
        })
        .finally(() => {
          submitBtn.innerHTML = originalText;
          submitBtn.disabled = false;
        });
    };
  }

  // --- ANNOUNCEMENT LIVE PREVIEW ---
  const annForm = document.getElementById('announcement-form');
  const previewCard = document.getElementById('preview-card');
  const previewContent = document.getElementById('preview-content');

  if (annForm && previewCard && previewContent) {
    const updatePreview = () => {
      const title = annForm.title.value.trim() || '(no title)';
      const message = (annForm.message.value.trim() || '(no message)').replace(/\n/g, '<br>');
      const category = annForm.category.value;
      const target = annForm.target_role.value;
      const pinned = annForm.pinned.checked;

      previewContent.innerHTML = `
        <div class="announcement-item ${pinned ? 'pinned' : ''}">
          <div class="announcement-header">
            <h3>${title}</h3>
            <div class="announcement-meta">
              ${category ? `<span class="badge">${category}</span>` : ''}
              <span>${target === 'all' ? 'All' : target.charAt(0).toUpperCase() + target.slice(1)}</span>
              ${pinned ? '<i class="fas fa-thumbtack pinned-icon" title="Pinned"></i>' : ''}
            </div>
          </div>
          <div class="announcement-body">
            <p>${message}</p>
          </div>
        </div>
      `;
      previewCard.style.display = 'block';
    };

    ['title', 'message', 'category', 'target_role'].forEach(id => {
      annForm[id].addEventListener('input', updatePreview);
    });
    annForm.pinned.addEventListener('change', updatePreview);

    // Auto-save draft
    const saveDraft = () => {
      const draft = {
        title: annForm.title.value,
        message: annForm.message.value,
        category: annForm.category.value,
        target_role: annForm.target_role.value,
        pinned: annForm.pinned.checked
      };
      localStorage.setItem('announcement_draft', JSON.stringify(draft));
    };
    annForm.addEventListener('input', () => setTimeout(saveDraft, 500));

    // Load draft
    const saved = localStorage.getItem('announcement_draft');
    if (saved) {
      const data = JSON.parse(saved);
      annForm.title.value = data.title || '';
      annForm.message.value = data.message || '';
      annForm.category.value = data.category || '';
      annForm.target_role.value = data.target_role || 'all';
      annForm.pinned.checked = data.pinned || false;
      updatePreview();
    }

    annForm.addEventListener('submit', () => {
      setTimeout(() => localStorage.removeItem('announcement_draft'), 1000);
    });
  }

  // --- CHARTS: Initialize (admin_report.html) ---
  function initCharts() {
    const ctxPie = document.getElementById('staffPieChart');
    const ctxBar = document.getElementById('appointmentBarChart');
    const ctxLine = document.getElementById('monthlyLineChart');

    if (ctxPie && window.staffPieData) {
      new Chart(ctxPie, { type: 'pie', data: window.staffPieData, options: { responsive: true } });
    }
    if (ctxBar && window.appointmentBarData) {
      new Chart(ctxBar, { type: 'bar', data: window.appointmentBarData, options: { responsive: true } });
    }
    if (ctxLine && window.monthlyAppointmentsData) {
      new Chart(ctxLine, { type: 'line', data: window.monthlyAppointmentsData, options: { responsive: true } });
    }
  }

  // --- TABLE SEARCH ---
  function initTableSearch() {
    document.querySelectorAll('.table-search').forEach(input => {
      input.addEventListener('keyup', function () {
        const filter = this.value.toLowerCase();
        const rows = this.closest('table').tBodies[0].rows;
        Array.from(rows).forEach(row => {
          row.style.display = row.textContent.toLowerCase().includes(filter) ? '' : 'none';
        });
      });
    });
  }

  // --- DARK MODE TOGGLE ---
  function initDarkMode() {
    const darkModeToggle = document.getElementById('darkModeToggle');
    if (!darkModeToggle) return;

    const savedTheme = localStorage.getItem('preferredTheme');
    const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
    const isDark = savedTheme === 'dark' || (!savedTheme && prefersDark);

    // Apply theme
    document.documentElement.dataset.theme = isDark ? 'dark' : 'light';
    darkModeToggle.checked = isDark;

    // Toggle handler
    darkModeToggle.addEventListener('change', function () {
      const newTheme = this.checked ? 'dark' : 'light';
      document.documentElement.dataset.theme = newTheme;
      localStorage.setItem('preferredTheme', newTheme);
      showAlert('success', `Switched to ${newTheme === 'dark' ? 'Dark' : 'Light'} Mode`);
    });

    // Listen to OS theme changes
    window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', e => {
      if (!localStorage.getItem('preferredTheme')) {
        const newTheme = e.matches ? 'dark' : 'light';
        document.documentElement.dataset.theme = newTheme;
        darkModeToggle.checked = e.matches;
      }
    });
  }

  // --- DOM READY ---
  document.addEventListener('DOMContentLoaded', () => {
    initCharts();
    initTableSearch();
    initDarkMode(); // Dark mode initialized here
  });

  // Export for HTML onclick
  window.openCreateModal = openCreateModal;
  window.closeCreateModal = closeCreateModal;
  window.openDeleteModal = openDeleteModal;
  window.closeDeleteModal = closeDeleteModal;
  window.copyToClipboard = copyToClipboard;
  window.showAlert = showAlert;

  console.log('admin.js loaded – with Dark Mode, clean & ready!');
})();