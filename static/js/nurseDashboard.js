// static/js/nurseDashboard.js

document.addEventListener('DOMContentLoaded', () => {
    // Refresh patient data
    function updatePatients() {
        fetch('/nurse_dashboard', {
            headers: { 'Accept': 'application/json' }
        })
        .then(response => response.json())
        .then(data => {
            if (data.patients) {
                const patientList = document.getElementById('patient-list');
                if (patientList) patientList.innerHTML = data.patients.map(p => `<li>${p.first_name} ${p.last_name}</li>`).join('');
            }
        })
        .catch(error => console.error('Error updating patients:', error));
    }

    setInterval(updatePatients, 60000); // Update every minute
    updatePatients(); // Initial update
});

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
});