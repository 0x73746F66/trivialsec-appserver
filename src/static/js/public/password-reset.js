const saveFields = async() => {
    const recaptcha_token = document.getElementById('recaptcha_token').value
    const confirmation_url = document.getElementById('confirmation_url').value
    const password1 = document.getElementById('new_password').value
    const password2 = document.getElementById('repeat_password').value
    if (password1 != password2) {
        appMessage('error', 'Passwords do not match')
        return;
    }
    const response = await fetch('/change-password', {
        credentials: 'same-origin',
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
            recaptcha_token,
            confirmation_url,
            password1,
            password2
        })
    }).catch(err => {
        appMessage('error', 'An unexpected error occurred. Please refresh the page and try again.')
        console.log(err)
    })
    const json = await response.json()
    if (json.status && json.status == 'error') {
        appMessage(json.status, json.message)
        console.log(json)
        refresh_recaptcha_token('password_reset_action')
    }
    if (json.status && json.status == 'success') {
        appMessage(json.status, json.message)
        setTimeout(()=>{window.location.href = '/login'}, 5000)
    }
}
if (recaptcha_site_key) {
    grecaptcha.ready(() => {
        refresh_recaptcha_token('password_reset_action')
    })
}
document.addEventListener('DOMContentLoaded', () => {
    if (location.pathname != '/password-reset') {
        history.pushState({}, document.title, '/password-reset')
    }
    const el = document.getElementById('save_password')
    el.addEventListener('click', saveFields, false)
    el.addEventListener('touchstart', saveFields, supportsPassive ? { passive: true } : false)
}, false)
