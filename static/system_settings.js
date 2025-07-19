// static/js/system_setting.js

document.addEventListener('DOMContentLoaded', () => {
    const form = document.getElementById('settings-form');
    if (form) {
        form.addEventListener('submit', (e) => {
            const backupFrequency = document.getElementById('backup-frequency').value;
            if (!backupFrequency) {
                e.preventDefault();
                alert('Backup frequency is required.');
            }
        });
    }
});