if (recaptcha_site_key) {
    grecaptcha.ready(() => {
        refresh_recaptcha_token('register_action')
    })
}
document.addEventListener('DOMContentLoaded', () => {
    if (location.pathname != '/register') {
        history.pushState({}, document.title, '/register')
    }
    document.getElementById('register_form').addEventListener('submit', async(e) => {
        e.preventDefault()
        const token = document.getElementById('recaptcha_token').value
        const json = await Api.post_async('/api/register', {
            alias: e.currentTarget.querySelector('#company_name').value,
            email: e.currentTarget.querySelector('#email').value,
            password: e.currentTarget.querySelector('#password').value,
            password2: e.currentTarget.querySelector('#password2').value,
            recaptcha_token: token
        }).catch(()=>appMessage('error', 'An unexpected error occurred. Please refresh the page and try again.'))
        console.log(json)
        appMessage(json.status, json.message)
        if (json.status == 'success') {
            setTimeout(()=>{window.location.href = '/login'}, 5000)
            return;
        }
        refresh_recaptcha_token('register_action')
    }, false)
}, false)