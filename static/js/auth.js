document.addEventListener('DOMContentLoaded', () => {
    const loginForm = document.querySelector('form[action="/login"]');
    if (loginForm) {
        loginForm.addEventListener('submit', async (e) => {
            e.preventDefault();

            // Basic validation
            const username = loginForm.querySelector('#username').value.trim();
            const password = loginForm.querySelector('#password').value.trim();
            const messageDiv = document.createElement('div');
            messageDiv.id = 'message';

            if (!username || !password) {
                messageDiv.textContent = 'Please fill in all fields.';
                messageDiv.className = 'error';
                loginForm.appendChild(messageDiv);
                return;
            }

            // Prepare form data
            const formData = new FormData(loginForm);

            try {
                const response = await fetch('/login', {
                    method: 'POST',
                    body: formData
                });
                const text = await response.text(); // Get raw response for flashed messages

                // Clear previous message
                const existingMessage = document.getElementById('message');
                if (existingMessage) existingMessage.remove();

                // Assume server returns HTML with flashed messages
                const parser = new DOMParser();
                const doc = parser.parseFromString(text, 'text/html');
                const flashedMessages = doc.querySelectorAll('.success, .error');
                if (flashedMessages.length > 0) {
                    flashedMessages.forEach(msg => {
                        messageDiv.textContent = msg.textContent;
                        messageDiv.className = msg.className;
                        loginForm.appendChild(messageDiv);
                    });
                } else {
                    messageDiv.textContent = 'Login processed. Check redirection.';
                    messageDiv.className = 'success';
                    loginForm.appendChild(messageDiv);
                }
            } catch (error) {
                messageDiv.textContent = 'An error occurred. Please try again.';
                messageDiv.className = 'error';
                loginForm.appendChild(messageDiv);
                console.error('Fetch error:', error);
            }
        });
    }

    // Optional: Add similar handling for register form if needed
    const registerForm = document.querySelector('form[action="/register"]');
    if (registerForm) {
        registerForm.addEventListener('submit', async (e) => {
            e.preventDefault();

            const username = registerForm.querySelector('#username').value.trim();
            const password = registerForm.querySelector('#password').value.trim();
            const email = registerForm.querySelector('#email').value.trim();
            const role = registerForm.querySelector('#role').value.trim();
            const messageDiv = document.createElement('div');
            messageDiv.id = 'message';

            if (!username || !password || !email || !role) {
                messageDiv.textContent = 'Please fill in all fields.';
                messageDiv.className = 'error';
                registerForm.appendChild(messageDiv);
                return;
            }

            const formData = new FormData(registerForm);

            try {
                const response = await fetch('/register', {
                    method: 'POST',
                    body: formData
                });
                const text = await response.text();

                const existingMessage = document.getElementById('message');
                if (existingMessage) existingMessage.remove();

                const parser = new DOMParser();
                const doc = parser.parseFromString(text, 'text/html');
                const flashedMessages = doc.querySelectorAll('.success, .error');
                if (flashedMessages.length > 0) {
                    flashedMessages.forEach(msg => {
                        messageDiv.textContent = msg.textContent;
                        messageDiv.className = msg.className;
                        registerForm.appendChild(messageDiv);
                    });
                } else {
                    messageDiv.textContent = 'Registration processed. Check redirection.';
                    messageDiv.className = 'success';
                    registerForm.appendChild(messageDiv);
                }
            } catch (error) {
                messageDiv.textContent = 'An error occurred. Please try again.';
                messageDiv.className = 'error';
                registerForm.appendChild(messageDiv);
                console.error('Fetch error:', error);
            }
        });
    }
});