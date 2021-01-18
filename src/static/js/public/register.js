if (recaptcha_site_key) {
    grecaptcha.ready(() => {
        refresh_recaptcha_token('register_action')
    })
}
const register_action = async(e) => {
    e.preventDefault()
    const token = document.getElementById('recaptcha_token').value
    const alias = document.querySelector('#company_name').value
    const email = document.querySelector('#email').value
    const password = document.querySelector('#password').value
    const password2 = document.querySelector('#password2').value
    if (!email) {
        appMessage('info', 'An email address must be provided')
    }
    if (!password || !password2 || (password2 !== password)) {
        appMessage('warning', 'Password do not match')
    }
    const response = await fetch('/register', {
        credentials: 'omit',
        method: 'POST',
        body: JSON.stringify({
            alias: alias,
            email: email,
            password: password,
            password2: password2,
            recaptcha_token: token
        }),
        headers: {'Content-Type': 'application/json'},
    }).catch(err => {
        appMessage('error', 'An unexpected error occurred. Please refresh the page and try again.')
        console.log(err)
    })
    const json = await response.json()
    if (!!json) {
        appMessage(json.status, json.message)
        if (json.status == 'retry') {
            refresh_recaptcha_token('register_action')
            return await register_action(e)
        } else if (json.status == 'success') {
            setTimeout(()=>{window.location.href = '/login'}, 5000)
            return;
        }
    }
    refresh_recaptcha_token('register_action')
}
document.addEventListener('DOMContentLoaded', () => {
    if (location.pathname != '/register') {
        history.pushState({}, document.title, '/register')
    }
    const register_btn = document.getElementById('register_btn')
    register_btn.addEventListener('click', register_action, false)
    register_btn.addEventListener('touchstart', register_action, supportsPassive ? { passive: true } : false)
}, false)
