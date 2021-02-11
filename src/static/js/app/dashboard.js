document.addEventListener('DOMContentLoaded', async() => {
    if (location.pathname != '/dashboard') {
        history.pushState({}, document.title, '/dashboard')
    }
}, false)
