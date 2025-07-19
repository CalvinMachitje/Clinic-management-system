document.addEventListener('DOMContentLoaded', () => {
    const staffPieCtx = document.getElementById('staffPieChart').getContext('2d');
    const appointmentBarCtx = document.getElementById('appointmentBarChart').getContext('2d');
    const monthlyLineCtx = document.getElementById('monthlyLineChart').getContext('2d');

    new Chart(staffPieCtx, {
        type: 'pie',
        data: window.staffPieData,
        options: {
            responsive: true,
            plugins: {
                legend: { position: 'bottom' }
            }
        }
    });

    new Chart(appointmentBarCtx, {
        type: 'bar',
        data: window.appointmentBarData,
        options: {
            responsive: true,
            scales: {
                y: { beginAtZero: true, ticks: { stepSize: 1 } }
            },
            plugins: { legend: { display: false } }
        }
    });

    new Chart(monthlyLineCtx, {
        type: 'line',
        data: window.monthlyAppointmentsData,
        options: {
            responsive: true,
            scales: {
                y: { beginAtZero: true, ticks: { stepSize: 1 } }
            }
        }
    });
});
