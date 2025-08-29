// Wait for the DOM to fully load
document.addEventListener('DOMContentLoaded', () => {
    const sidebar = document.querySelector('.sidebar');
    const mainContent = document.querySelector('.main-content');
    const toggleButton = document.createElement('button'); // Create a toggle button for mobile

    // Add toggle button to navbar for mobile
    toggleButton.classList.add('sidebar-toggle');
    toggleButton.innerHTML = '<i class="fas fa-bars"></i>';
    document.querySelector('.navbar').appendChild(toggleButton);

    // Toggle sidebar visibility on mobile
    toggleButton.addEventListener('click', () => {
        sidebar.classList.toggle('open');
        mainContent.classList.toggle('shifted');
    });

    // Smooth scroll for anchor links
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            document.querySelector(this.getAttribute('href')).scrollIntoView({
                behavior: 'smooth'
            });
        });
    });

    // Hero image fade-in animation
    const heroImage = document.querySelector('.hero-image img');
    if (heroImage) {
        heroImage.style.opacity = '0';
        setTimeout(() => {
            heroImage.style.transition = 'opacity 0.5s';
            heroImage.style.opacity = '1';
        }, 100);
    }

    document.addEventListener('DOMContentLoaded', () => {
    // ... existing code ...

    // Update current time
    function updateTime() {
        const now = new Date();
        const options = { hour: 'numeric', minute: '2-digit', hour12: true, timeZoneName: 'short' };
        document.documentElement.style.setProperty('--current-time', now.toLocaleTimeString('en-ZA', options));
    }
    updateTime(); // Initial call
    setInterval(updateTime, 60000); // Update every minute
    });

    // Media query for mobile responsiveness
    const mediaQuery = window.matchMedia('(max-width: 768px)');
    function handleMobileView(e) {
        if (e.matches) {
            sidebar.classList.remove('open');
            mainContent.classList.remove('shifted');
        } else {
            sidebar.classList.add('open');
        }
    }
    mediaQuery.addListener(handleMobileView);
    handleMobileView(mediaQuery);
});

// Ensure Font Awesome icons are available (if not already included in base.html)
if (!document.querySelector('link[href*="fontawesome"]')) {
    const fontAwesome = document.createElement('link');
    fontAwesome.rel = 'stylesheet';
    fontAwesome.href = 'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.4/css/all.min.css';
    document.head.appendChild(fontAwesome);
}

document.addEventListener('DOMContentLoaded', () => {
    const newsContainer = document.querySelector('.news-cards');
    const apiKey = 'your_newsapi_key_here'; // Not recommended: use server-side instead
    const url = `https://newsapi.org/v2/top-headlines?category=health&country=za&pageSize=5&apiKey=${apiKey}`;

    fetch(url)
        .then(response => response.json())
        .then(data => {
            newsContainer.innerHTML = ''; // Clear static content
            if (data.articles && data.articles.length > 0) {
                data.articles.forEach(article => {
                    const card = document.createElement('div');
                    card.className = 'card';
                    card.innerHTML = `
                        <h3>${article.title}</h3>
                        <p>${article.publishedAt.slice(0, 10)} - ${article.description || 'No description available.'}</p>
                        <a href="${article.url}" target="_blank" class="btn">Read More</a>
                    `;
                    newsContainer.appendChild(card);
                });
            } else {
                newsContainer.innerHTML = '<div class="card"><h3>No News Available</h3><p>Unable to fetch health news at this time.</p></div>';
            }
        })
        .catch(error => {
            console.error('Error fetching news:', error);
            newsContainer.innerHTML = '<div class="card"><h3>No News Available</h3><p>Unable to fetch health news at this time.</p></div>';
        });
});