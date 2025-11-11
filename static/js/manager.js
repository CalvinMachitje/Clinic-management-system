// manager.js — All Manager Dashboard JS
// Works with: manager_announcements.html, manager_dashboard.html, etc.

document.addEventListener('DOMContentLoaded', function () {
  console.log('Manager.js loaded');

  // === 1. ANNOUNCEMENT / DIRECT MESSAGE TOGGLE ===
  const msgTypeRadios = document.querySelectorAll('input[name="msg_type"]');
  const announcementFields = document.getElementById('announcementFields');
  const directFields = document.getElementById('directFields');
  const pinnedCheckbox = document.querySelector('input[name="pinned"]');

  function toggleMessageType() {
    const isDirect = document.querySelector('input[name="msg_type"]:checked').value === 'direct';
    if (announcementFields) announcementFields.style.display = isDirect ? 'none' : 'block';
    if (directFields) directFields.style.display = isDirect ? 'block' : 'none';
    if (pinnedCheckbox) pinnedCheckbox.disabled = isDirect;
  }

  msgTypeRadios.forEach(radio => {
    radio.addEventListener('change', () => {
      toggleMessageType();
      if (radio.value === 'direct') loadStaffList();
    });
  });

  // Initial state
  toggleMessageType();

  // === 2. LOAD STAFF FOR DIRECT MESSAGES ===
  async function loadStaffList() {
    const select = document.getElementById('targetUserSelect');
    if (!select) return;

    try {
      const res = await fetch('/api/staff_list');
      const staff = await res.json();
      select.innerHTML = '<option value="">-- Select Staff --</option>';
      staff.forEach(s => {
        const opt = document.createElement('option');
        opt.value = s.staff_number;
        opt.textContent = `${s.first_name} ${s.last_name} (${s.role.charAt(0).toUpperCase() + s.role.slice(1)})`;
        select.appendChild(opt);
      });
    } catch (err) {
      console.error('Failed to load staff:', err);
    }
  }

  // Load staff when direct message is selected
  const directRadio = document.querySelector('input[value="direct"]');
  if (directRadio && directRadio.checked) loadStaffList();

  // === 3. SEND MESSAGE (Announcement or Direct) ===
  const sendForm = document.getElementById('sendMessageForm');
  if (sendForm) {
    sendForm.onsubmit = async function (e) {
      e.preventDefault();
      const formData = new FormData(this);
      const submitBtn = this.querySelector('button[type="submit"]');
      submitBtn.disabled = true;
      submitBtn.textContent = 'Sending...';

      try {
        const res = await fetch('/manager_send_message', {
          method: 'POST',
          body: formData
        });
        const data = await res.json();

        if (data.success) {
          alert('Message sent successfully!');
          this.reset();
          toggleMessageType(); // Reset UI
        } else {
          alert('Error: ' + (data.message || 'Unknown error'));
        }
      } catch (err) {
        alert('Network error. Please try again.');
        console.error(err);
      } finally {
        submitBtn.disabled = false;
        submitBtn.textContent = 'Send Now';
      }
    };
  }

  // === 4. LIVE PREVIEW (Optional) ===
  const previewCard = document.getElementById('preview-card');
  const previewContent = document.getElementById('preview-content');

  if (previewCard && previewContent) {
    const inputs = ['title', 'message', 'category', 'target_role', 'pinned'];
    inputs.forEach(id => {
      const el = document.getElementById(id);
      if (el) el.addEventListener('input', updatePreview);
    });

    function updatePreview() {
      const title = document.getElementById('title').value || 'Untitled';
      const message = document.getElementById('message').value || 'No message.';
      const category = document.getElementById('category').value || 'general';
      const target = document.getElementById('target_role').value;
      const pinned = document.getElementById('pinned').checked;

      let targetText = 'All Staff';
      if (target && target !== 'all') {
        targetText = target.charAt(0).toUpperCase() + target.slice(1) + (target === 'manager' ? 's' : 's') + ' Only';
      }

      previewContent.innerHTML = `
        <div class="announcement-header">
          <h3>${title}</h3>
          <div class="announcement-meta">
            <span class="author">You</span>
            <span class="timestamp">Just now</span>
            <span class="badge">${category.charAt(0).toUpperCase() + category.slice(1)}</span>
            <span class="target-role">${targetText}</span>
            ${pinned ? '<i class="fas fa-thumbtack pinned-icon" title="Pinned"></i>' : ''}
          </div>
        </div>
        <div class="announcement-body">
          <p>${message.replace(/\n/g, '<br>')}</p>
        </div>
      `;
      previewCard.style.display = 'block';
    }
  }

  // === 5. REAL-TIME MESSAGE FEED (SSE) ===
  const feedContainer = document.getElementById('messagesFeed') || document.getElementById('announcementsContainer');
  if (feedContainer && '{{ session.user_id }}') {
    const myRole = '{{ session.role }}';
    const myId = '{{ session.user_id }}';

    let list = feedContainer.querySelector('.announcement-list');
    let emptyState = feedContainer.querySelector('.empty-state');

    const evtSource = new EventSource('/stream_messages');

    evtSource.onmessage = function (e) {
      const msg = JSON.parse(e.data);

      // Determine if message is for this user
      const isForMe = msg.target_role === 'all' ||
                      msg.target_role === myRole ||
                      msg.target_user === myId;

      if (!isForMe) return;

      // Build target text
      let targetText = 'All Staff';
      if (msg.target_role && msg.target_role !== 'all') {
        targetText = msg.target_role === 'manager' ? 'Managers' :
                     msg.target_role.charAt(0).toUpperCase() + msg.target_role.slice(1) + 's';
      } else if (msg.target_text) {
        targetText = msg.target_text;
      }

      const item = document.createElement('div');
      item.className = 'announcement-item' + (msg.pinned ? ' pinned' : '');
      item.innerHTML = `
        <div class="announcement-header">
          <h3>${msg.title || 'Direct Message'}</h3>
          <div class="meta">
            <span class="author">${msg.author}</span>
            <span class="timestamp">Just now</span>
            ${msg.category ? `<span class="category badge">${msg.category.charAt(0).toUpperCase() + msg.category.slice(1)}</span>` : ''}
            <span class="target badge">${targetText}</span>
            ${msg.pinned ? '<i class="fas fa-thumbtack pinned-icon" title="Pinned"></i>' : ''}
          </div>
        </div>
        <div class="announcement-body">
          <p>${msg.message.replace(/\n/g, '<br>')}</p>
        </div>
      `;

      // Insert at top
      if (!list) {
        list = document.createElement('ul');
        list.className = 'announcement-list';
        feedContainer.innerHTML = '';
        feedContainer.appendChild(list);
        if (emptyState) emptyState.remove();
      }
      list.prepend(item);
    };

    evtSource.onerror = function () {
      console.warn('SSE connection error. Reconnecting...');
    };
  }
});

const data = (( report_data | tojson ));

new Chart(document.getElementById('financeChart'), {
  type: 'bar',
  data: {
    labels: data.months,
    datasets: [
      { label: 'Revenue', data: data.revenue, backgroundColor: '#28a745' },
      { label: 'Expenses', data: data.expenses, backgroundColor: '#dc3545' }
    ]
  }
});

new Chart(document.getElementById('patientChart'), {
  type: 'line',
  data: {
    labels: data.months,
    datasets: [{ label: 'Patients', data: data.patients, borderColor: '#007bff', tension: 0.4 }]
  }
});

document.getElementById('download-pdf').onclick = () => {
  const { jsPDF } = window.jspdf;
  const doc = new jsPDF();
  doc.setFontSize(18);
  doc.text('Township Clinic - Executive Report', 20, 20);
  doc.setFontSize(12);
  doc.text(`Period: ${data.months[0]} - ${data.months[data.months.length-1]}`, 20, 30);
  doc.text(`Total Revenue: R${data.revenue.reduce((a,b)=>a+b,0).toFixed(2)}`, 20, 40);
  doc.save('executive-report.pdf');
};

function reorder(id, qty) {
  if (confirm(`Reorder ${qty} units?`)) {
    fetch('/reorder_item', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id, quantity: qty })
    }).then(() => location.reload());
  }
}

document.addEventListener('DOMContentLoaded', function () {
  const calendarEl = document.getElementById('calendar');
  const modal = document.getElementById('shiftModal');
  const form = document.getElementById('shiftForm');
  let calendar;

  function showAlert(message, type = 'danger') {
    const alert = document.createElement('div');
    alert.className = `alert alert-${type} fixed top-4 left-1/2 transform -translate-x-1/2 z-50 p-4 rounded shadow-lg`;
    alert.innerHTML = `${message} <button class="float-right">&times;</button>`;
    document.body.appendChild(alert);
    alert.querySelector('button').onclick = () => alert.remove();
    setTimeout(() => alert.remove(), 5000);
  }

  function initCalendar() {
    calendar = new FullCalendar.Calendar(calendarEl, {
      initialView: 'dayGridMonth',
      headerToolbar: { left: 'prev,next today', center: 'title', right: 'dayGridMonth,timeGridWeek' },
      editable: true,
      droppable: true,
      events: '/get_schedule',
      eventClick: function(info) {
        document.getElementById('eventId').value = info.event.id;
        document.getElementById('employee_id').value = info.event.extendedProps.employee_id;
        document.getElementById('shift_date').value = info.event.startStr.split('T')[0];
        document.getElementById('shift_type').value = info.event.extendedProps.shift_type;
        document.getElementById('notes').value = info.event.extendedProps.notes || '';
        modal.showModal();
      },
      eventDrop: function(info) {
        updateEvent(info.event);
      },
      dateClick: function(info) {
        document.getElementById('eventId').value = '';
        document.getElementById('shift_date').value = info.dateStr;
        modal.showModal();
      }
    });
    calendar.render();
  }

  initCalendar();

  form.onsubmit = async function(e) {
    e.preventDefault();
    const data = {
      id: document.getElementById('eventId').value,
      employee_id: document.getElementById('employee_id').value,
      shift_date: document.getElementById('shift_date').value,
      shift_type: document.getElementById('shift_type').value,
      notes: document.getElementById('notes').value
    };

    const response = await fetch('/save_shift', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data)
    });

    if (response.ok) {
      modal.close();
      calendar.refetchEvents();
      showAlert('Shift saved successfully!', 'success');
    } else {
      const result = await response.json();
      showAlert(`Error: ${result.message || 'Conflict!'}`, 'danger');
    }
  };

  function updateEvent(event) {
    fetch('/update_shift_date', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id: event.id, shift_date: event.startStr.split('T')[0] })
    });
  }

  // Export buttons
  document.getElementById('export-pdf').onclick = () => {
    const { jsPDF } = window.jspdf;
    const doc = new jsPDF();
    doc.text('Staff Schedule - Township Clinic', 20, 20);
    doc.text(`Generated: ${new Date().toLocaleString()}`, 20, 30);
    doc.save('staff-schedule.pdf');
  };

  document.getElementById('export-csv').onclick = () => {
    fetch('/get_schedule').then(r => r.json()).then(events => {
      let csv = 'Staff,Date,Shift,Notes\n';
      events.forEach(e => {
        csv += `"${e.title}","${e.start.split('T')[0]}","${e.extendedProps.shift_type}","${e.extendedProps.notes || ''}"\n`;
      });
      const blob = new Blob([csv], { type: 'text/csv' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url; a.download = 'staff-schedule.csv'; a.click();
    });
  };
});

// manager.js - All Manager Module Scripts
document.addEventListener('DOMContentLoaded', function () {
    initCalendar();
    initStaffEdit();
});

// FullCalendar
function initCalendar() {
    const calendarEl = document.getElementById('calendar');
    if (!calendarEl) return;

    const calendar = new FullCalendar.Calendar(calendarEl, {
        initialView: 'dayGridMonth',
        headerToolbar: {
            left: 'prev,next today',
            center: 'title',
            right: 'dayGridMonth,timeGridWeek,timeGridDay'
        },
        events: '/api/schedule',
        eventClick: function(info) {
            openShiftModal(info.event);
        },
        selectable: true,
        select: function(info) {
            document.getElementById('shift_date').value = info.startStr;
            openModal('shiftModal');
        }
    });
    calendar.render();

    // Export Buttons
    document.getElementById('export-pdf')?.addEventListener('click', () => exportCalendar('pdf'));
    document.getElementById('export-csv')?.addEventListener('click', () => exportCalendar('csv'));
}

function openShiftModal(event) {
    document.getElementById('eventId').value = event.id || '';
    document.getElementById('shift_date').value = event.startStr;
    document.getElementById('shift_type').value = event.extendedProps.shift || 'morning';
    document.getElementById('notes').value = event.extendedProps.notes || '';
    openModal('shiftModal');
}

function exportCalendar(format) {
    if (format === 'pdf') {
        const { jsPDF } = window.jspdf;
        const doc = new jsPDF();
        doc.text('Staff Schedule', 14, 15);
        doc.save('schedule.pdf');
    }
}

// Staff Edit
function initStaffEdit() {
    const form = document.getElementById('editStaffForm');
    if (!form) return;

    form.onsubmit = async (e) => {
        e.preventDefault();
        const id = document.getElementById('edit_staff_id').value;
        const data = {
            first_name: document.getElementById('edit_first_name').value,
            last_name: document.getElementById('edit_last_name').value,
            email: document.getElementById('edit_email').value,
            phone: document.getElementById('edit_phone').value
        };

        await fetch(`/api/staff/${id}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data)
        });
        closeModal('editStaffModal');
        location.reload();
    };
}

function editStaff(id) {
    fetch(`/api/staff/${id}`)
        .then(r => r.json())
        .then(data => {
            document.getElementById('edit_staff_id').value = data.id;
            document.getElementById('edit_first_name').value = data.first_name;
            document.getElementById('edit_last_name').value = data.last_name;
            document.getElementById('edit_email').value = data.email || '';
            document.getElementById('edit_phone').value = data.phone || '';
            openModal('editStaffModal');
        });
}

// Modal Helpers
function openModal(id) {
    document.getElementById(id).showModal();
}

function closeModal(id) {
    document.getElementById(id).close();
}

document.querySelectorAll('.progress[data-score]').forEach(bar => {
    const score = bar.dataset.score || 0;
    bar.style.setProperty('--score', `${score}%`);
  });

  document.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('.progress[data-score]').forEach(bar => {
      const score = bar.dataset.score || '0';
      bar.style.setProperty('--score', `${score}%`);
    });
  });

  // Leave Actions
document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('.approve-leave, .reject-leave').forEach(btn => {
    btn.addEventListener('click', async () => {
      const id = btn.dataset.id;
      const action = btn.classList.contains('approve-leave') ? 'approve' : 'reject';
      
      try {
        const res = await fetch('/manager/leave_action', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'X-CSRFToken': document.querySelector('meta[name="csrf-token"]').content
          },
          body: `id=${id}&action=${action}`
        });
        
        if (res.ok) {
          btn.closest('.flex').remove();
        }
      } catch (err) {
        console.error('Leave action failed:', err);
      }
    });
  });

  // Schedule Review
  document.querySelectorAll('.schedule-review').forEach(btn => {
    btn.addEventListener('click', () => {
      const id = btn.dataset.id;
      // Open modal or redirect to review form
      alert(`Scheduling review for staff ID: ${id}`);
    });
  });

  // View Training Details
  document.querySelectorAll('.view-training').forEach(btn => {
    btn.addEventListener('click', () => {
      const id = btn.dataset.id;
      // Open modal or redirect
      alert(`Training details for ID: ${id}`);
    });
  });

  // View Compliance
  window.viewCompliance = (type) => {
    // Open modal or redirect
    alert(`Compliance details for ${type}`);
  };

  // Launch Survey
  window.launchSurvey = () => {
    // Open survey form
    alert('Launching staff survey...');
  };

  // View Burnout Reports
  window.viewBurnoutReports = () => {
    // Open reports
    alert('Viewing burnout reports...');
  };
});