// static/js/patients_list.js

document.addEventListener('DOMContentLoaded', () => {
    const searchInput = document.getElementById('search-patient');
    if (searchInput) {
        searchInput.addEventListener('input', () => {
            const term = searchInput.value.toLowerCase();
            const rows = document.querySelectorAll('#patients-table tbody tr');
            rows.forEach(row => {
                const text = row.textContent.toLowerCase();
                row.style.display = text.includes(term) ? '' : 'none';
            });
        });
    }
});