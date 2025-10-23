document.addEventListener('DOMContentLoaded', () => {
    const form = document.querySelector('form');

    // Form submission handling
    form.addEventListener('submit', (e) => {
        e.preventDefault();
        const username = document.getElementById('username').value;
        const password = document.getElementById('password').value;

        if (!username || !password) {
            alert('Please fill in all required fields.');
            return;
        }
        if (password.length < 6) {
            alert('Password must be at least 6 characters long.');
            return;
        }

        // Simulate login (replace with actual backend logic)
        alert(`Logging in with username ${username}...`);
        // Add actual form submission or API call here
        form.submit();
    });
});