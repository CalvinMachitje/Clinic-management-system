// static/js/patientRegistration.js

document.addEventListener('DOMContentLoaded', () => {
    const form = document.getElementById('patient-form');
    if (form) {
        form.addEventListener('submit', (e) => {
            const firstName = document.getElementById('first_name').value;
            const lastName = document.getElementById('last_name').value;
            if (!firstName || !lastName) {
                e.preventDefault();
                alert('First name and last name are required.');
            }
        });
    }
});