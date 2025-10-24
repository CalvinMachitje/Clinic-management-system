document.addEventListener('DOMContentLoaded', function () {
    const popup       = document.getElementById('successPopup');
    const overlay     = document.getElementById('popupOverlay');
    const closeBtn    = document.getElementById('closePopup');
    const popupDate   = document.getElementById('popupDate');
    const popupDoctor = document.getElementById('popupDoctor');

    if (!popup || !overlay || !closeBtn || !popupDate || !popupDoctor) return;

    const date   = popup.dataset.date;
    const doctor = popup.dataset.doctor;

    if (date && doctor) {
        popupDate.textContent   = date;
        popupDoctor.textContent = doctor;
        popup.classList.add('show');
        overlay.classList.add('show');

        setTimeout(() => {
            popup.classList.remove('show');
            overlay.classList.remove('show');
        }, 5000);
    }

    function closePopup() {
        popup.classList.remove('show');
        overlay.classList.remove('show');
    }

    closeBtn.addEventListener('click', closePopup);
    overlay.addEventListener('click', closePopup);
});