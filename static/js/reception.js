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

async function bookAppointment(event, patientId) {
    event.preventDefault();
    const form = event.target;
    const formData = new FormData(form);
    try {
        const response = await fetch('/search_patient', {
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
            const appointmentCell = row.querySelector('.appointment-cell');
            appointmentCell.innerHTML = `${data.appointment.appointment_date} (Reason: ${data.appointment.reason || 'N/A'}) <form onsubmit="cancelAppointment(event, '${data.appointment.id}')" class="inline"><input type="hidden" name="appointment_id" value="${data.appointment.id}"><button type="submit" class="btn btn-danger ml-2">Cancel</button></form>`;
            form.classList.add('hidden');
        }
    } catch (error) {
        const flashMessages = document.getElementById('flash-messages') || document.querySelector('.flash-messages');
        const alert = document.createElement('div');
        alert.className = 'alert alert-error';
        alert.textContent = 'An error occurred while booking the appointment.';
        flashMessages.appendChild(alert);
        console.error('Book error:', error);
    }
}

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
if (document.getElementById('waitlist-table-body')) {
    setupSSE();
}