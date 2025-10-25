// admin.js - Interactive functionality for Admin Dashboard
// Handles charts, forms, modals, and dynamic updates
// Dependencies: Chart.js (loaded in templates), jQuery optional but not required here

(function() {
  'use strict';

  // Utility Functions
  function logError(message, error) {
    console.error(`[Admin JS Error] ${message}`, error);
  }

  function showAlert(type, message) {
    // Create or update flash-like alert
    let alert = document.querySelector('.admin-alert');
    if (!alert) {
      alert = document.createElement('div');
      alert.className = 'admin-alert alert alert-' + type;
      alert.innerHTML = `
        <i class="fas fa-${type === 'success' ? 'check-circle' : 'exclamation-circle'}"></i>
        ${message}
        <button class="close" onclick="this.parentElement.remove()">
          <i class="fas fa-times"></i>
        </button>
      `;
      document.querySelector('.container')?.insertBefore(alert, document.querySelector('.container').firstChild);
    } else {
      alert.className = `admin-alert alert alert-${type}`;
      alert.innerHTML = `
        <i class="fas fa-${type === 'success' ? 'check-circle' : 'exclamation-circle'}"></i>
        ${message}
        <button class="close" onclick="this.parentElement.remove()">
          <i class="fas fa-times"></i>
        </button>
      `;
    }
    setTimeout(() => alert?.remove(), 5000);
  }

  // Chart Initialization (for admin_report.html)
  function initCharts() {
    const ctxPie = document.getElementById('staffPieChart');
    const ctxBar = document.getElementById('appointmentBarChart');
    const ctxLine = document.getElementById('monthlyLineChart');

    if (!ctxPie && !ctxBar && !ctxLine) return; // Exit if no charts

    // Staff Pie Chart
    if (ctxPie && window.staffPieData) {
      new Chart(ctxPie, {
        type: 'pie',
        data: window.staffPieData,
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: {
              position: 'bottom',
              labels: { padding: 20, usePointStyle: true }
            },
            tooltip: {
              callbacks: {
                label: function(context) {
                  return `${context.label}: ${context.parsed}%`;
                }
              }
            }
          },
          animation: {
            animateRotate: true,
            duration: 1500
          }
        }
      });
    }

    // Appointment Bar Chart
    if (ctxBar && window.appointmentBarData) {
      new Chart(ctxBar, {
        type: 'bar',
        data: window.appointmentBarData,
        options: {
          responsive: true,
          maintainAspectRatio: false,
          scales: {
            y: {
              beginAtZero: true,
              ticks: { stepSize: 1 }
            }
          },
          plugins: {
            legend: { display: false },
            tooltip: {
              callbacks: {
                label: function(context) {
                  return `${context.dataset.label}: ${context.parsed.y}`;
                }
              }
            }
          },
          animation: {
            duration: 1000,
            easing: 'easeOutQuart'
          }
        }
      });
    }

    // Monthly Line Chart
    if (ctxLine && window.monthlyAppointmentsData) {
      new Chart(ctxLine, {
        type: 'line',
        data: window.monthlyAppointmentsData,
        options: {
          responsive: true,
          maintainAspectRatio: false,
          scales: {
            y: {
              beginAtZero: true,
              ticks: { stepSize: 5 }
            },
            x: {
              grid: { display: false }
            }
          },
          plugins: {
            legend: { display: true, position: 'top' },
            tooltip: {
              mode: 'index',
              intersect: false
            }
          },
          animation: {
            duration: 1500,
            easing: 'easeInOutQuart'
          },
          elements: {
            line: { tension: 0.4 },
            point: { radius: 5, hoverRadius: 8 }
          }
        }
      });
    }
  }

  // Form Validation & Submission (for edit_employee.html, systemSettings.html)
  function initForms() {
    const forms = document.querySelectorAll('#edit-profile-form, #settings-form, #delete-user-form');
    forms.forEach(form => {
      form.addEventListener('submit', function(e) {
        const requiredFields = form.querySelectorAll('[required]');
        let isValid = true;

        requiredFields.forEach(field => {
          if (!field.value.trim()) {
            field.classList.add('error');
            isValid = false;
            showAlert('error', `Please fill in ${field.name || 'this field'}.`);
          } else {
            field.classList.remove('error');
          }
        });

        if (!isValid) {
          e.preventDefault();
          return false;
        }

        // Show loading state
        const submitBtn = form.querySelector('button[type="submit"]');
        if (submitBtn) {
          const originalText = submitBtn.innerHTML;
          submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Saving...';
          submitBtn.disabled = true;

          // Reset on completion (handled by server response)
          setTimeout(() => {
            submitBtn.innerHTML = originalText;
            submitBtn.disabled = false;
          }, 2000); // Fallback
        }
      });
    });

    // Image preview for edit profile
    const imageInput = document.getElementById('profile_image');
    if (imageInput) {
      imageInput.addEventListener('change', function(e) {
        const file = e.target.files[0];
        if (file) {
          const reader = new FileReader();
          reader.onload = function(e) {
            document.getElementById('imagePreview').src = e.target.result;
          };
          reader.readAsDataURL(file);
        }
      });
    }
  }

  // static/js/admin.js
document.addEventListener('DOMContentLoaded', () => {
  const form = document.getElementById('announcement-form');
  const previewCard = document.getElementById('preview-card');
  const previewContent = document.getElementById('preview-content');

  if (!form || !previewCard) return;

  const updatePreview = () => {
    const title = form.title.value.trim();
    const message = form.message.value.trim();
    const category = form.category.value;
    const target = form.target_role.value;
    const pinned = form.pinned.checked;

    if (!title && !message) {
      previewCard.style.display = 'none';
      return;
    }

    previewCard.style.display = 'block';
    previewContent.innerHTML = `
      <div class="announcement-item ${pinned ? 'pinned' : ''}">
        <div class="announcement-header">
          <h3>${title || '<em>Untitled</em>'}</h3>
          <div class="announcement-meta">
            <span class="author">You</span>
            <span class="timestamp">Just now</span>
            ${category ? `<span class="badge">${category}</span>` : ''}
            <span class="target-role">
              ${target === 'all' ? 'All' : target.charAt(0).toUpperCase() + target.slice(1)}
            </span>
            ${pinned ? `<i class="fas fa-thumbtack pinned-icon" title="Pinned"></i>` : ''}
          </div>
        </div>
        <div class="announcement-body">
          <p>${message.replace(/\n/g, '<br>') || '<em>No message</em>'}</p>
        </div>
      </div>
    `;
  };

  // Live preview
  ['title', 'message', 'category', 'target_role'].forEach(id => {
    form[id].addEventListener('input', updatePreview);
  });
  form.pinned.addEventListener('change', updatePreview);

  // Auto-save draft
  const saveDraft = () => {
    const draft = {
      title: form.title.value,
      message: form.message.value,
      category: form.category.value,
      target_role: form.target_role.value,
      pinned: form.pinned.checked
    };
    localStorage.setItem('announcement_draft', JSON.stringify(draft));
  };

  form.addEventListener('input', () => setTimeout(saveDraft, 500));

  // Load saved draft
  const saved = localStorage.getItem('announcement_draft');
  if (saved) {
    const data = JSON.parse(saved);
    form.title.value = data.title || '';
    form.message.value = data.message || '';
    form.category.value = data.category || '';
    form.target_role.value = data.target_role || 'all';
    form.pinned.checked = data.pinned || false;
    updatePreview();
  }

  // Clear draft on submit
  form.addEventListener('submit', () => {
    setTimeout(() => localStorage.removeItem('announcement_draft'), 1000);
  });
});

  // User Management Interactions (for manageUsers.html)
  function initUserManagement() {
    const deleteButtons = document.querySelectorAll('.delete-user');
    const confirmationModal = document.getElementById('delete-confirmation');
    const cancelDelete = document.getElementById('cancel-delete');

    deleteButtons.forEach(btn => {
      btn.addEventListener('click', function() {
        const userId = this.dataset.userId;
        document.getElementById('delete-user-id').value = userId;
        if (confirmationModal) {
          confirmationModal.style.display = 'block';
          confirmationModal.querySelector('h3').textContent = `Delete User ID: ${userId}?`;
        }
      });
    });

    if (cancelDelete) {
      cancelDelete.addEventListener('click', function() {
        if (confirmationModal) confirmationModal.style.display = 'none';
      });
    }

    // Close modal on outside click
    if (confirmationModal) {
      confirmationModal.addEventListener('click', function(e) {
        if (e.target === this) this.style.display = 'none';
      });
    }
  }

  // Dynamic Theme Switcher (enhance if needed)
  function initThemeSwitcher() {
    const themeSelect = document.querySelector('.theme-form select');
    if (themeSelect) {
      themeSelect.addEventListener('change', function() {
        document.documentElement.dataset.theme = this.value;
        localStorage.setItem('preferredTheme', this.value); // Persist choice
        showAlert('success', `Theme switched to ${this.value}.`);
      });
    }
  }

  // Search/Filter for Tables (generic for admin tables)
  function initTableSearch() {
    const searchInputs = document.querySelectorAll('.table-search');
    searchInputs.forEach(input => {
      input.addEventListener('keyup', function() {
        const filter = this.value.toLowerCase();
        const table = this.closest('table');
        const rows = table.tBodies[0].rows;

        Array.from(rows).forEach(row => {
          const text = row.textContent.toLowerCase();
          row.style.display = text.includes(filter) ? '' : 'none';
        });
      });
    });
  }

  // Initialize All Components on DOM Ready
  document.addEventListener('DOMContentLoaded', function() {
    initCharts();
    initForms();
    initUserManagement();
    initThemeSwitcher();
    initTableSearch();

    // Responsive adjustments
    function handleResize() {
      const sidebar = document.getElementById('sidebar');
      const main = document.getElementById('main-content');
      if (window.innerWidth >= 1024) {
        sidebar.classList.add('active');
        main.classList.add('active');
      } else {
        sidebar.classList.remove('active');
        main.classList.remove('active');
      }
    }
    window.addEventListener('resize', handleResize);
    handleResize(); // Initial call
  });

  // Export utilities for global use if needed
  window.AdminUtils = {
    showAlert: showAlert,
    logError: logError
  };

  console.log('Admin JS loaded successfully.');
})();