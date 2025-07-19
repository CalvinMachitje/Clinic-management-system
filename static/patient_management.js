const patients = [
    { id: "P001", name: "John Doe", condition: "Hypertension" },
    { id: "P002", name: "Jane Roe", condition: "Diabetes" }
];

function loadPatientTable() {
    const tbody = document.getElementById('patient-table-body');
    tbody.innerHTML = '';
    patients.forEach(patient => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td>${patient.id}</td>
            <td>${patient.name}</td>
            <td>${patient.condition}</td>
            <td>
                <button onclick="editPatient('${patient.id}')">Edit</button>
                <button onclick="deletePatient('${patient.id}')">Delete</button>
            </td>
        `;
        tbody.appendChild(tr);
    });
}

function searchPatients() {
    const searchTerm = document.getElementById('patient-search').value.toLowerCase();
    const filteredPatients = patients.filter(patient =>
        patient.name.toLowerCase().includes(searchTerm) ||
        patient.id.toLowerCase().includes(searchTerm) ||
        patient.condition.toLowerCase().includes(searchTerm)
    );
    const tbody = document.getElementById('patient-table-body');
    tbody.innerHTML = '';
    filteredPatients.forEach(patient => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td>${patient.id}</td>
            <td>${patient.name}</td>
            <td>${patient.condition}</td>
            <td>
                <button onclick="editPatient('${patient.id}')">Edit</button>
                <button onclick="deletePatient('${patient.id}')">Delete</button>
            </td>
        `;
        tbody.appendChild(tr);
    });
}

function editPatient(id) {
    alert(`Edit patient ${id} - TBD`);
}

function deletePatient(id) {
    if (confirm(`Are you sure you want to delete patient ${id}?`)) {
        const index = patients.findIndex(p => p.id === id);
        if (index !== -1) {
            patients.splice(index, 1);
            loadPatientTable();
        }
    }
}

document.addEventListener('DOMContentLoaded', () => {
    if (!currentUser) return;

    loadPatientTable();
    document.getElementById('add-patient-btn').addEventListener('click', () => {
        document.getElementById('add-patient-form').classList.toggle('form-hidden');
        document.getElementById('add-patient-form').classList.toggle('form-visible');
    });

    document.getElementById('patient-form').addEventListener('submit', (e) => {
        e.preventDefault();
        const newPatient = {
            id: document.getElementById('patient-id').value,
            name: document.getElementById('patient-name').value,
            condition: document.getElementById('patient-condition').value
        };
        patients.push(newPatient);
        loadPatientTable();
        document.getElementById('patient-form').reset();
        document.getElementById('add-patient-form').classList.add('form-hidden');
        document.getElementById('add-patient-form').classList.remove('form-visible');
    });

    document.getElementById('cancel-patient').addEventListener('click', () => {
        document.getElementById('patient-form').reset();
        document.getElementById('add-patient-form').classList.add('form-hidden');
        document.getElementById('add-patient-form').classList.remove('form-visible');
    });

    document.getElementById('back-to-dashboard').addEventListener('click', () => {
        window.location.href = 'dashboard.html';
    });
});