const saveBillingEmail = async() => {
    const billing_email = document.getElementById('billing_email').value
    const password = document.getElementById('billing_password').value
    const json = await Api.post_async('/v1/account', [
        {prop: 'billing_email', value: billing_email},
        {prop: 'password', value: password}
    ]).catch(()=>appMessage('error', 'An unexpected error occurred. Please refresh the page and try again.'))
    appMessage(json.status, json.message)
    if (json.status == 'error') {
        console.log(json)
    }
}

document.addEventListener('DOMContentLoaded', async() => {
    if (location.pathname != '/account/subscription') {
        history.pushState({}, document.title, '/account/subscription')
    }
    sidebar()
    livetime()
    setInterval(livetime, 1000)
    document.querySelectorAll('select').forEach(el => { new Choices(el, { searchEnabled: true }) })
    for await(const el of document.querySelectorAll('.toggle-sidenav')) {
        el.addEventListener('click', toggler, false)
        el.addEventListener('touchstart', toggler, supportsPassive ? { passive: true } : false)
    }
    for await(const el of document.querySelectorAll('.menu-opener')) {
        el.addEventListener('click', toggler, false)
        el.addEventListener('touchstart', toggler, supportsPassive ? { passive: true } : false)
    }
    const emailChangeEl = document.getElementById('billing-email-button')
    emailChangeEl.addEventListener("click", saveBillingEmail, false)
    emailChangeEl.addEventListener("touchstart", saveBillingEmail, supportsPassive ? { passive: true } : false)

}, false)