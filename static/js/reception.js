function openModal(id) {
    document.getElementById(id).setAttribute("open", "true");
}

function closeModal(id) {
    document.getElementById(id).removeAttribute("open");
}

function toggleAppointmentForm(patientId) {
    const form = document.getElementById(`appointment-form-${patientId}`);
    form.classList.toggle('hidden');
}

async function cancelAppointment(event, appointmentId) {
    event.preventDefault();
    const form = event.target;
    const formData = new FormData(form);
    try {
        const response = await fetch('/cancel_appointment', {
            method: 'POST',
            body: formData,
            headers: { 'X-Requested-With': 'XMLHttpRequest' }
        });
        const data = await response.json();
        const flashMessages = document.getElementById('flash-messages') || document.querySelector('.flash-messages');
        const alert = document.createElement('div');
        alert.className = `alert alert-${data.success ? 'success' : 'error'}`;
        alert.textContent = data.message;
        flashMessages.appendChild(alert);
        if (data.success) {
            const row = form.closest('tr');
            row.querySelector('.appointment-cell').innerHTML = 'None';
        }
    } catch (error) {
        const flashMessages = document.getElementById('flash-messages') || document.querySelector('.flash-messages');
        const alert = document.createElement('div');
        alert.className = 'alert alert-error';
        alert.textContent = 'An error occurred while cancelling the appointment.';
        flashMessages.appendChild(alert);
        console.error('Cancel error:', error);
    }
}

async function bookAppointment(event) {
    event.preventDefault();
    const form = event.target;
    const formData = new FormData(form);
    try {
        const response = await fetch('/manage_appointments', {
            method: 'POST',
            body: formData,
            headers: { 'X-Requested-With': 'XMLHttpRequest' },
            credentials: 'include' // For session handling
        });
        const data = await response.json();
        const flashMessages = document.getElementById('flash-messages') || document.querySelector('.flash-messages');
        const messageDiv = form.querySelector('#formMessage');
        if (messageDiv) {
            messageDiv.textContent = data.message;
            messageDiv.className = `mt-4 ${data.success ? 'text-green-600' : 'text-red-600'}`;
        } else if (flashMessages) {
            const alert = document.createElement('div');
            alert.className = `alert alert-${data.success ? 'success' : 'error'}`;
            alert.textContent = data.message;
            flashMessages.appendChild(alert);
        }
        if (data.success) {
            setTimeout(() => location.reload(), 1000); // Refresh to show new appointment
        }
    } catch (error) {
        console.error('Book error:', error);
        const messageDiv = form.querySelector('#formMessage');
        if (messageDiv) {
            messageDiv.textContent = 'An error occurred while booking the appointment.';
            messageDiv.className = 'mt-4 text-red-600';
        }
    }
}

async function convertSelfBooked(event) {
    event.preventDefault();
    const form = event.target;
    const formData = new FormData(form);
    try {
        const response = await fetch('/manage_appointments', {
            method: 'POST',
            body: formData,
            headers: { 'X-Requested-With': 'XMLHttpRequest' },
            credentials: 'include'
        });
        const data = await response.json();
        const messageDiv = form.querySelector('#formMessage');
        if (messageDiv) {
            messageDiv.textContent = data.message;
            messageDiv.className = `mt-4 ${data.success ? 'text-green-600' : 'text-red-600'}`;
        }
        if (data.success) {
            setTimeout(() => location.reload(), 1000); // Refresh to update table
        }
    } catch (error) {
        console.error('Convert error:', error);
        const messageDiv = form.querySelector('#formMessage');
        if (messageDiv) {
            messageDiv.textContent = 'An error occurred while converting the appointment.';
            messageDiv.className = 'mt-4 text-red-600';
        }
    }
}

document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('statusFilter').addEventListener('change', (e) => {
        const status = e.target.value;
        const rows = document.querySelectorAll('#appointmentsTable tbody tr');
        rows.forEach(row => {
            const rowStatus = row.getAttribute('data-status');
            row.style.display = status === 'all' || (status === 'open' && ['scheduled', 'waiting'].includes(rowStatus)) || rowStatus === status.toLowerCase() ? '' : 'none';
        });
    });
});

// SSE for checkIn.html and reception_dashboard.html
function setupSSE() {
    const source = new EventSource('/stream_appointments');
    source.onmessage = function(event) {
        try {
            const update = JSON.parse(event.data);
            console.log('Appointment update:', update);
            const waitlistTbody = document.getElementById('waitlist-table-body');
            if (waitlistTbody) {
                const row = waitlistTbody.querySelector(`tr[data-appointment-id="${update.id}"]`);
                if (update.status === 'helped' && row) {
                    row.remove();
                } else if (!row && update.status === 'waiting') {
                    const newRow = document.createElement('tr');
                    newRow.setAttribute('data-appointment-id', update.id);
                    newRow.innerHTML = `
                        <td>${update.id}</td>
                        <td>${update.first_name} ${update.last_name}</td>
                        <td>${update.appointment_date}</td>
                        <td>${update.status}</td>
                        <td>${update.reason || 'Not specified'}</td>
                        <td>
                            <form action="/assign_staff" method="POST" class="inline">
                                <input type="hidden" name="appointment_id" value="${update.id}">
                                <select name="staff_id" required class="form-control mr-2">
                                    <option value="">Select Staff</option>
                                    <!-- Staff options populated dynamically -->
                                </select>
                                <button type="submit" class="btn btn-primary">Assign</button>
                            </form>
                        </td>
                    `;
                    waitlistTbody.prepend(newRow);
                }
            }
        } catch (e) {
            console.error('Error processing SSE data:', e);
        }
    };
}

// Initialize SSE on checkIn.html
function setupSSE() {
    const source = new EventSource('/stream_appointments');
    source.onmessage = function(event) {
        try {
            const update = JSON.parse(event.data);
            console.log('Appointment update:', update);
            const waitlistTbody = document.getElementById('waitlist-table-body');
            if (waitlistTbody) {
                const row = waitlistTbody.querySelector(`tr[data-appointment-id="${update.id}"]`);
                if (update.status === 'helped' && row) {
                    row.remove();
                } else if (!row && update.status === 'waiting') {
                    const newRow = document.createElement('tr');
                    newRow.setAttribute('data-appointment-id', update.id);
                    newRow.innerHTML = `
                        <td>${update.id}</td>
                        <td>${update.first_name} ${update.last_name}</td>
                        <td>${update.appointment_date}</td>
                        <td>${update.status}</td>
                        <td>${update.reason || 'Not specified'}</td>
                        <td>
                            <form action="/assign_staff" method="POST" class="inline">
                                <input type="hidden" name="appointment_id" value="${update.id}">
                                <select name="staff_id" required class="form-control mr-2">
                                    <option value="">Select Staff</option>
                                    <!-- Staff options populated dynamically -->
                                </select>
                                <button type="submit" class="btn btn-primary">Assign</button>
                            </form>
                        </td>
                    `;
                    waitlistTbody.prepend(newRow);
                }
            }
        } catch (e) {
            console.error('Error processing SSE data:', e);
        }
    };
}

// 1. Initial Load
async function loadAnnouncements() {
    const res = await fetch(`/api/${getRole()}/announcements`);
    const announcements = await res.json();
    renderAnnouncements(announcements);
}

// 2. Live Updates
function startAnnouncementStream() {
    const evtSource = new EventSource('/api/announcements/stream');
    evtSource.onmessage = (e) => {
        const newAnn = JSON.parse(e.data);
        prependAnnouncement(newAnn);  // Add to top
        showToast(`New: ${newAnn.title}`, 'info');
    };
    evtSource.onerror = () => {
        console.error("SSE disconnected. Reconnecting...");
        evtSource.close();
        setTimeout(startAnnouncementStream, 3000);
    };
}

function getRole() {
    return document.body.dataset.role || 'unknown'; // Set in base.html
}

// Render function
function renderAnnouncements(anns) {
    const container = document.getElementById('announcements-container');
    container.innerHTML = anns.map(a => `
        <div class="announcement-item ${a.pinned ? 'pinned' : ''}">
            <h3>${a.title} ${a.pinned ? '<i class="fas fa-thumbtack"></i>' : ''}</h3>
            <p class="meta">${a.author} • ${a.timestamp} ${a.category ? `<span class="badge">${a.category}</span>` : ''}</p>
            <p>${a.message.replace(/\n/g, '<br>')}</p>
        </div>
    `).join('');
}

function prependAnnouncement(ann) {
    const container = document.getElementById('announcements-container');
    const div = document.createElement('div');
    div.className = `announcement-item ${ann.pinned ? 'pinned' : ''}`;
    div.innerHTML = `
        <h3>${ann.title} ${ann.pinned ? '<i class="fas fa-thumbtack"></i>' : ''}</h3>
        <p class="meta">${ann.author} • ${ann.timestamp}</p>
        <p>${ann.message.replace(/\n/g, '<br>')}</p>
    `;
    container.insertBefore(div, container.firstChild);
}

// Init
document.addEventListener('DOMContentLoaded', () => {
    loadAnnouncements();
    startAnnouncementStream();

    // === DARK MODE TOGGLE (ADDED) ===
    function initDarkMode() {
        const darkModeToggle = document.getElementById('darkModeToggle');
        if (!darkModeToggle) return;

        const savedTheme = localStorage.getItem('preferredTheme');
        const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
        const isDark = savedTheme === 'dark' || (!savedTheme && prefersDark);

        document.documentElement.dataset.theme = isDark ? 'dark' : 'light';
        darkModeToggle.checked = isDark;

        darkModeToggle.addEventListener('change', function () {
            const newTheme = this.checked ? 'dark' : 'light';
            document.documentElement.dataset.theme = newTheme;
            localStorage.setItem('preferredTheme', newTheme);
            if (typeof showToast === 'function') {
                showToast(`Switched to ${newTheme} mode`, 'info');
            }
        });

        window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', e => {
            if (!localStorage.getItem('preferredTheme')) {
                const newTheme = e.matches ? 'dark' : 'light';
                document.documentElement.dataset.theme = newTheme;
                darkModeToggle.checked = e.matches;
            }
        });
    }

    initDarkMode();
});