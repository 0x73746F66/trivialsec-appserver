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
        const json = await Api.post_async('/api/subscribe', {
            email: e.currentTarget.querySelector('#email').value,
            recaptcha_token: token
        }).catch(()=>appMessage('error', 'An unexpected error occurred. Please refresh the page and try again.'))
        appMessage(json.status, json.message)
        refresh_recaptcha_token('subscribe_action')
    }, false)
}, false)
