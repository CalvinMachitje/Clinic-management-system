// static/js/defaultPage.js - Homepage Menu Toggle (Slide-in Animation)
(function() {
  'use strict';

  console.log('defaultPage.js loaded - Initializing homepage menu.');  // Debug

  // Homepage Mobile Menu Toggle
  function initHomepageMenu() {
    const toggleBtn = document.getElementById('menu-toggle');
    const menu = document.getElementById('mobile-menu');
    const overlay = document.getElementById('mobile-overlay') || createOverlay();  // Create if missing

    if (!toggleBtn || !menu) {
      console.warn('Menu elements not found (#menu-toggle or #mobile-menu).');
      return;
    }

    let isOpen = false;

    function toggleMenu() {
      isOpen = !isOpen;
      menu.classList.toggle('active', isOpen);  // FIXED: Use class for CSS animation
      overlay.classList.toggle('active', isOpen);
      toggleBtn.innerHTML = isOpen ? '<i class="fas fa-times"></i>' : '<i class="fas fa-bars"></i>';
      toggleBtn.setAttribute('aria-expanded', isOpen);
      console.log('Menu toggled:', isOpen ? 'open (sliding in)' : 'closed (sliding out)');  // Debug
    }

    toggleBtn.addEventListener('click', toggleMenu);
    overlay.addEventListener('click', () => { if (isOpen) toggleMenu(); });  // Close on overlay click

    // Keyboard: Escape to close
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape' && isOpen) toggleMenu();
    });

    // Close on resize (e.g., desktop)
    window.addEventListener('resize', () => {
      if (window.innerWidth > 768 && isOpen) toggleMenu();
    });

    console.log('Homepage menu init complete.');
  }

  // Create overlay if not in HTML
  function createOverlay() {
    const overlay = document.createElement('div');
    overlay.id = 'mobile-overlay';
    overlay.className = 'mobile-overlay';
    document.body.appendChild(overlay);
    console.log('Created overlay dynamically.');
    return overlay;
  }

  // Dashboard Fallback (if loaded on dashboard pages - optional)
  function initDashboardIfNeeded() {
    const dashToggle = document.getElementById('menu-toggle-btn');
    if (dashToggle) {
      console.log('Dashboard detected - running sidebar init.');
      // Add your dashboard sidebar code here if needed (from previous fixes)
    }
  }

  // Init on DOM ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
      initHomepageMenu();
      initDashboardIfNeeded();
    });
  } else {
    initHomepageMenu();
    initDashboardIfNeeded();
  }
})();