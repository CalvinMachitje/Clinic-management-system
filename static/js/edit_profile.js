// static/js/edit_profile.js

document.addEventListener('DOMContentLoaded', () => {
    const form = document.getElementById('profile-form');
    if (form) {
        form.addEventListener('submit', (e) => {
            const email = document.getElementById('email').value;
            const firstName = document.getElementById('first_name').value;
            const lastName = document.getElementById('last_name').value;
            if (!email || !firstName || !lastName) {
                e.preventDefault();
                alert('Email, first name, and last name are required.');
            }
        });
    }
});