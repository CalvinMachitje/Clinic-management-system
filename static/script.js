document.querySelectorAll('[onclick*="modal"]').forEach(button => {
    button.addEventListener('click', () => {
        document.getElementById('addPatientModal').style.display = 'block';
    });
});