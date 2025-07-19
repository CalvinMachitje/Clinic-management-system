// static/js/user_management.js

document.addEventListener('DOMContentLoaded', () => {
    const addUserForm = document.getElementById('add-user-form');
    if (addUserForm) {
        addUserForm.addEventListener('submit', (e) => {
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            const email = document.getElementById('email').value;
            const role = document.getElementById('role').value;
            if (!username || !password || !email || !role) {
                e.preventDefault();
                alert('All fields (username, password, email, role) are required.');
            }
        });
    }

    const deleteButtons = document.querySelectorAll('.delete-btn');
    deleteButtons.forEach(button => {
        button.addEventListener('click', () => {
            if (!confirm('Are you sure you want to delete this user?')) {
                event.preventDefault();
            }
        });
    });
});