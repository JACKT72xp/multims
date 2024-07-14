document.addEventListener("DOMContentLoaded", function() {
    const root = '/';
    const useHash = true;
    const router = new Navigo(root, useHash);

    router
        .on({
            'home': function() {
                loadPage('home.html');
            },
            'port-forward': function() {
                loadPage('port-forward.html');
            },
            'settings': function() {
                loadPage('settings.html');
            },
            'about': function() {
                loadPage('about.html');
            },
            'console': function() {
                window.location.href = "/console";
            },
            '*': function() {
                loadPage('home.html');
            }
        })
        .resolve();

    function toggleMenu() {
        var menu = document.getElementById('menu');
        menu.classList.toggle('active');
    }

    document.addEventListener("click", function(event) {
        var menu = document.getElementById('menu');
        var menuToggle = document.querySelector(".navbar-toggler");

        if (menu.classList.contains('active') && !menu.contains(event.target) && !menuToggle.contains(event.target)) {
            menu.classList.remove('active');
        }
    });

    function loadPage(page) {
        var content = document.getElementById('main-content');
        fetch('/static/templates/' + page)
            .then(response => {
                if (!response.ok) {
                    throw new Error('Page not found');
                }
                return response.text();
            })
            .then(data => {
                content.innerHTML = data;
                if (page === 'home.html') {
                    checkConfig();
                }
            })
            .catch(error => console.error('Error loading page:', error));
    }

    function checkConfig() {
        fetch('/check-config')
            .then(response => {
                if (!response.ok) {
                    throw new Error('Network response was not ok');
                }
                return response.json();
            })
            .then(data => {
                var content = document.getElementById('main-content');
                if (!data.exists) {
                    content.innerHTML += `
                        <div class="alert alert-warning" role="alert">
                            <strong>Multims configuration file not found!</strong> Please initialize your project by running <code>multims init</code>.
                        </div>
                    `;
                } else {
                    content.innerHTML += `
                        <div class="alert alert-success" role="alert">
                            <strong>Multims configuration file found!</strong> You're ready to go.
                        </div>
                    `;
                }
            })
            .catch(error => console.error('Error fetching or parsing configuration data:', error));
    }

    document.addEventListener("DOMContentLoaded", function() {
        router.resolve();
    });
});
