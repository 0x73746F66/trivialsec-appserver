if (recaptcha_site_key) {
    grecaptcha.ready(() => {
        refresh_recaptcha_token('subscribe_action')
    })
}
document.addEventListener('DOMContentLoaded', async() => {
    if (location.pathname != '/') {
        history.pushState({}, document.title, '/')
    }
    document.getElementById('subscribe_form').addEventListener('submit', async(e) => {
        e.preventDefault()
        const token = document.getElementById('recaptcha_token').value
        const response = await fetch('/subscribe', {
            credentials: 'same-origin',
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                recaptcha_token: token,
                email: document.getElementById('email').value,
            })
        }).catch(err => {
            appMessage('error', 'An unexpected error occurred. Please refresh the page and try again.')
            console.log(err)
        })
        const json = await response.json()
        appMessage(json.status, json.message)
        refresh_recaptcha_token('subscribe_action')
    }, false)
}, false)
