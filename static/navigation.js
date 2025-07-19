document.addEventListener('DOMContentLoaded', () => {
    if (!currentUser) return;
    
    const navLinks = document.getElementById('nav-links');
    if (!navLinks) return;

    const links = {
        Administrator: [
            { text: 'Patient Management', href: 'patient_management.html' },
            { text: 'User Management', href: 'user_management.html' },
            { text: 'System Settings', href: 'system_setting.html' }
        ],
        Doctor: [
            { text: 'Patient Management', href: 'patient_management.html' },
            { text: 'Doctor Module', href: 'doctorPage.html' }
        ],
        Nurse: [
            { text: 'Patient Management', href: 'patient_management.html' },
            { text: 'Nurse Module', href: 'nursePage.html' }
        ]
    };

    navLinks.innerHTML = '';
    links[currentUser.role].forEach(link => {
        const li = document.createElement('li');
        const a = document.createElement('a');
        a.href = link.href;
        a.textContent = link.text;
        li.appendChild(a);
        navLinks.appendChild(li);
    });
});