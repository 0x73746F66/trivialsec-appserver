const stripe = Stripe(app.stripe_publishable_key)

const buttonActions = async(event) => {
    if (event.currentTarget.id == 'plan_enterprise') {
        appMessage('info', 'Please contact us to activate your Enterprise plan')
        return;
    }
    
    const json = await Api.post_async('/api/checkout', {
        selection: event.currentTarget.id
    }).catch(()=>appMessage('error', 'An unexpected error occurred. Please refresh the page and try again.'))
    if (json.status != 'success') {
        console.log(json)
        appMessage(json.status, json.message)
        return;
    }
    if (!json.result || !json.result.hasOwnProperty('id')) {
        console.log(json.result)
        appMessage('error', 'Failed to start Checkout with Stripe.com')
        return;
    }
    stripe.redirectToCheckout({sessionId: json.result['id']}).then(result => {
        if (result.error.message) {
            appMessage('error', result.error.message)
        }
    })
}

document.addEventListener('DOMContentLoaded', async() => {
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
    for await(const el of document.querySelectorAll('button')) {
        el.addEventListener('click', buttonActions, false)
        el.addEventListener('touchstart', buttonActions, supportsPassive ? { passive: true } : false)
    }

}, false)
