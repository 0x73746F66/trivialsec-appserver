const saveFields = async() => {
    const recaptcha_token = document.getElementById('recaptcha_token').value
    const confirmation_url = document.getElementById('confirmation_url').value
    const password1 = document.getElementById('new_password').value
    const password2 = document.getElementById('repeat_password').value
    if (password1 != password2) {
        appMessage('error', 'Passwords do not match')
        return;
    }
    const json = await Api.post_async('/v1/confirm-password', {
        recaptcha_token,
        confirmation_url,
        password1,
        password2
    }).catch(()=>appMessage('error', 'An unexpected error occurred. Please refresh the page and try again.'))
    appMessage(json.status, json.message)
    if (json.status == 'error') {
        console.log(json)
        refresh_recaptcha_token('invitation_action')
    }
    if (json.status == 'success') {
        setTimeout(()=>{window.location.href = '/app'}, 5000)
    }
}
if (recaptcha_site_key) {
    grecaptcha.ready(() => {
        refresh_recaptcha_token('invitation_action')
    })
}
document.addEventListener('DOMContentLoaded', () => {
    if (location.pathname != '/invitation') {
        history.pushState({}, document.title, '/invitation')
    }
    const el = document.getElementById('save_password')
    el.addEventListener('click', saveFields, false)
    el.addEventListener('touchstart', saveFields, supportsPassive ? { passive: true } : false)
}, false)
