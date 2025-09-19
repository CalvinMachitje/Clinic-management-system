document.addEventListener('DOMContentLoaded', () => {
  // Mobile menu toggle
  const toggle = document.getElementById('menu-toggle');
  const menu = document.getElementById('menu');
  if (toggle && menu) {
    toggle.addEventListener('click', () => {
      menu.classList.toggle('active');
    });
  }

  // Close dropdown on click outside
  document.addEventListener('click', (e) => {
    const dropdowns = document.querySelectorAll('.dropdown');
    dropdowns.forEach(dropdown => {
      if (!dropdown.contains(e.target)) {
        dropdown.querySelector('.dropdown-content').classList.add('hidden');
      }
    });
  });
});

document.getElementById('menu-toggle').addEventListener('click', () => {
  const mobileMenu = document.getElementById('mobile-menu');
  const mainContent = document.getElementById('main-content');
  mobileMenu.classList.toggle('active');
  mainContent.style.marginLeft = mobileMenu.classList.contains('active') ? '250px' : '0';
});