document.addEventListener('DOMContentLoaded', () => {
    const form = document.querySelector('form');

    // Form submission handling
    form.addEventListener('submit', (e) => {
        e.preventDefault();
        const username = document.getElementById('username').value;
        const email = document.getElementById('email').value;
        const password = document.getElementById('password').value;
        const firstName = document.getElementById('first_name').value;
        const lastName = document.getElementById('last_name').value;
        const role = document.getElementById('role').value;
        const terms = document.getElementById('terms').checked;

        if (!username || !email || !password || !firstName || !lastName || !role || !terms) {
            alert('Please fill in all fields and agree to the Terms and Conditions.');
            return;
        }
        if (password.length < 6) {
            alert('Password must be at least 6 characters long.');
            return;
        }

        // Simulate registration (replace with actual backend logic)
        alert(`Registering ${firstName} ${lastName} with username ${username} and email ${email}...`);
        // Add actual form submission or API call here
        form.submit();
    });
});