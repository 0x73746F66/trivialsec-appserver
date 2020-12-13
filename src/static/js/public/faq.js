const toggleFaq = event => {
    let el = event.currentTarget.querySelector('.faq-answer')
    if (el === event.target) return;
    if (el.classList.contains('open')) {
        el.classList.remove('open')
    } else {
        el.classList.add('open')
    }
}
if (recaptcha_site_key) {
    grecaptcha.ready(() => {
        refresh_recaptcha_token('subscribe_action')
    })
}
document.addEventListener('DOMContentLoaded', async() => {
    if (location.pathname != '/faq') {
        history.pushState({}, document.title, '/faq')
    }
    for await(const el of document.querySelectorAll('.faq-question')) {
        el.addEventListener('click', toggleFaq, false)
        el.addEventListener('touchstart', toggleFaq, supportsPassive ? { passive: true } : false)
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
