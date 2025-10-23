document.querySelectorAll('[onclick*="modal"]').forEach(button => {
    button.addEventListener('click', () => {
        document.getElementById('addPatientModal').style.display = 'block';
    });
});

console.log("scripts.js loaded for admin dashboard");
     document.addEventListener('DOMContentLoaded', function() {
         console.log("Admin dashboard initialized");
         // Add JavaScript for admin dashboard (e.g., toggle details, metrics updates)
         const detailsElements = document.querySelectorAll('details');
         detailsElements.forEach(detail => {
             detail.addEventListener('toggle', () => {
                 console.log(`${detail.querySelector('summary').textContent} toggled`);
             });
         });
     });

console.log("scripts.js loaded");
     document.addEventListener('DOMContentLoaded', function() {
         console.log("Page initialized");
         // Shared functionality for modals and forms
         const modals = document.querySelectorAll('.modal');
         modals.forEach(modal => {
             modal.addEventListener('click', (e) => {
                 if (e.target === modal) {
                     modal.removeAttribute('open');
                 }
             });
         });
         // Add form validation or other shared logic here
     });