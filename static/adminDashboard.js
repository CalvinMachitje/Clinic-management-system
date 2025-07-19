// static/js/adminDashboard.js

document.addEventListener('DOMContentLoaded', () => {
    // Refresh dashboard stats periodically
    function updateStats() {
        fetch('/adminDashboard.html', {
            headers: { 'Accept': 'application/json' }
        })
        .then(response => response.json())
        .then(data => {
            if (data.total_users) document.getElementById('total-users').textContent = data.total_users;
            if (data.active_staff) document.getElementById('active-staff').textContent = data.active_staff;
            if (data.system_alerts) document.getElementById('system-alerts').textContent = data.system_alerts;
        })
        .catch(error => console.error('Error updating stats:', error));
    }

    setInterval(updateStats, 60000); // Update every minute
    updateStats(); // Initial update
});