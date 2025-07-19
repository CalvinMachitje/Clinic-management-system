// static/js/doctorDashboard.js

document.addEventListener('DOMContentLoaded', () => {
    // Refresh patient data
    function updatePatients() {
        fetch('/doctor_dashboard', {
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