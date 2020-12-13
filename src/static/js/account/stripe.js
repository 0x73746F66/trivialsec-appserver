const stripe = Stripe(app.stripe_publishable_key)

const displayError = error => {
    let el = document.getElementById('card-errors')
    el.textContent = error.message
}
const showCardError = event => {
    if (event.error) {
        displayError(event.error)
    } else {
        document.getElementById('card-errors').textContent = ''
    }
}

const createSubscription = (paymentMethodId, priceId) => {
    return (
    Api.post('/api/create-subscription', {
        paymentMethodId: paymentMethodId,
        priceId: priceId,
    }).then(json => {
        if (json.status == 'error') {
            console.log(json)
            throw json
        }
        if (json.status == 'success') {
            return {
                paymentMethodId: paymentMethodId,
                priceId: priceId,
                subscription: json.result,
            }
        }
    })
    // If attaching this card to a Customer object succeeds,
    // but attempts to charge the customer fail, you
    // get a requires_payment_method error.
    .then((subscription, paymentMethodId, priceId) => {
        if (subscription.status === 'active') {
          // subscription is active, no customer actions required.
          return { subscription, priceId, paymentMethodId };
        } else if (subscription.latest_invoice.payment_intent.status === 'requires_payment_method') {
          // Using localStorage to manage the state of the retry here,
          // Store the latest invoice ID and status.
          localStorage.setItem('latestInvoiceId', subscription.latest_invoice.id)
          localStorage.setItem(
            'latestInvoicePaymentIntentStatus',
            subscription.latest_invoice.payment_intent.status
          )
          throw { error: { message: 'Your card was declined.' } }
        } else {
          return { subscription, priceId, paymentMethodId }
        }
      })
    // No more actions required. Provision your service for the user.
    .then(onSubscriptionComplete)
    .catch(displayError)
    )
}
function retryInvoiceWithNewPaymentMethod(paymentMethodId, invoiceId, priceId) {
    return (
        Api.post('/api/retry-invoice', {
            paymentMethodId: paymentMethodId,
            invoiceId: invoiceId,
            priceId: priceId,
        }).then(json => {
            // If the card is declined, display an error to the user.
            if (json.status == 'error') {
                console.log(json)
                throw json
            }
            if (json.status == 'success') {
                return json.result
            }
        })
        // Normalize the result to contain the object returned by Stripe.
        // Add the additional details we need.
        .then((result) => {
          return {
            // Use the Stripe 'object' property on the
            // returned result to understand what object is returned.
            paymentMethodId: paymentMethodId,
            priceId: priceId,
            invoice: result,
            isRetry: true,
          }
        })
        // No more actions required. Provision your service for the user.
        .then(onSubscriptionComplete)
        .catch(displayError)
    )
}
const onSubscriptionComplete = result => {
    if (// Payment was successful.
        (result.hasOwnProperty('invoice') && result.invoice.payment_intent.status === 'succeeded')||
        (result.hasOwnProperty('subscription') && result.subscription.status === 'active')
    ) {
        Api.post('/api/account', [{prop: 'is_setup', value: 1}]).then(json => {
            if (json.status == 'error') {
                console.log(json)
            }
            if (json.status == 'success') {
                appMessage('success', `Subscribed to ${result.subscription.items.data[0].price.product}`)
                setTimeout(()=>{window.location.href = '/app'}, 3000)
            }
        })
    }
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
    cardElement.mount("#card-element")
    cardElement.on('change', showCardError)
    subscriptionForm.addEventListener('submit', ev => {
        ev.preventDefault()
        // If a previous payment was attempted, get the latest invoice
        const latestInvoicePaymentIntentStatus = localStorage.getItem(
          'latestInvoicePaymentIntentStatus'
        )
        if (latestInvoicePaymentIntentStatus === 'requires_payment_method') {
          const invoiceId = localStorage.getItem('latestInvoiceId')
          const isPaymentRetry = true
          // create new payment method & retry payment on invoice with new payment method
          createPaymentMethod({
            card: cardElement.card,
            isPaymentRetry,
            invoiceId,
          })
        } else {
          // create new payment method & create subscription
          createPaymentMethod({ card: cardElement.card })
        }
      }, false)

}, false)
