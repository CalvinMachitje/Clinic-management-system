// static/js/reception.js

document.addEventListener('DOMContentLoaded', () => {
    // Form validation
    const forms = {
        'book-appointment-form': validateAppointmentForm,
        'record-visit-form': validateVisitForm,
        'transfer-patient-form': validateTransferForm,
        'emergency-request-form': validateEmergencyForm
    };

    Object.keys(forms).forEach(formId => {
        const form = document.getElementById(formId);
        if (form) {
            form.addEventListener('submit', (e) => {
                if (!forms[formId]()) {
                    e.preventDefault();
                    alert('Please fill in all required fields.');
                }
            });
        }
    });

    // Real-time notification polling
    function fetchNotifications() {
        fetch('/reception_dashboard', {
            method: 'GET',
            headers: { 'Accept': 'application/json' }
        })
        .then(response => response.json())
        .then(data => {
            if (data.messages) {
                const messageSection = document.querySelector('.message-section');
                if (messageSection) {
                    messageSection.innerHTML = '';
                    data.messages.forEach(msg => {
                        const div = document.createElement('div');
                        div.className = `message-card ${msg.title.includes('Available') ? 'availability-notification' : 
                            msg.title.includes('Unavailable') ? 'unavailability-notification' : ''}`;
                        div.innerHTML = `
                            <h4>${msg.title}</h4>
                            <p>${msg.content}</p> <!-- Fixed to use content instead of title -->
                            <small>${msg.date}</small>
                        `;
                        messageSection.appendChild(div);
                    });
                }
            }
        })
        .catch(error => console.error('Error fetching notifications:', error));
    }

    setInterval(fetchNotifications, 30000); // Poll every 30 seconds
    fetchNotifications(); // Initial fetch

    // Form validation functions
    function validateAppointmentForm() {
        const patientId = document.getElementById('patient_id').value;
        const firstName = document.getElementById('first_name').value;
        const lastName = document.getElementById('last_name').value;
        const appointmentTime = document.getElementById('appointment_time').value;
        return patientId && firstName && lastName && appointmentTime;
    }

    function validateVisitForm() {
        const patientId = document.getElementById('visit_patient_id').value;
        const visitTime = document.getElementById('visit_time').value;
        return patientId && visitTime;
    }

    function validateTransferForm() {
        const patientId = document.getElementById('transfer_patient_id').value;
        const toClinic = document.getElementById('to_clinic').value;
        return patientId && toClinic;
    }

    function validateEmergencyForm() {
        const patientId = document.getElementById('emergency_patient_id').value;
        const reason = document.getElementById('emergency_reason').value;
        return patientId && reason;
    }
});