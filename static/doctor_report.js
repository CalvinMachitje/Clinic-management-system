// static/js/doctor_report.js

document.addEventListener('DOMContentLoaded', () => {
    // Refresh report data
    function updateReport() {
        fetch('/doctor_report', {
            headers: { 'Accept': 'application/json' }
        })
        .then(response => response.json())
        .then(data => {
            if (data.total_patients) document.getElementById('total-patients').textContent = data.total_patients;
            if (data.today_appointments) document.getElementById('today-appointments').textContent = data.today_appointments;
        })
        .catch(error => console.error('Error updating report:', error));
    }

    setInterval(updateReport, 60000); // Update every minute
    updateReport(); // Initial update
});