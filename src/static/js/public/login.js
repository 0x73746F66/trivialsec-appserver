let tabWrapper = document.querySelector(".tab__content")
let activeTab = tabWrapper.querySelector(".active")

const eventTabSwitch = async(e) => {
    // Remove class from active tab
    for await(const ele of document.querySelectorAll(".tabs > li")) {
        ele.classList.remove("active")
    }

    // Add class active to clicked tab
    e.currentTarget.classList.add("active")

    // fade out active tab
    activeTab.querySelector('.content__wrapper').classList.add('hide')
    activeTab.querySelector('.content__wrapper').classList.remove('show')
        // Remove active class all tabs
    for await(const ele of document.querySelectorAll(".tab__content > li")) {
        ele.classList.remove("active")
    }

    // Add class active to corresponding tab
    document.querySelector(`.tab__content [data-tab="${e.currentTarget.dataset.tab}"]`).classList.add("active")

    // update new active tab
    activeTab = document.querySelector(".tab__content > .active")
    let activeTabHeight = activeTab.offsetHeight
    for await(const ele of document.querySelectorAll('.tab__content')) {
        if (ele.querySelector('.active') == activeTab) {
            ele.style.height = activeTabHeight
        }
    }

    activeTab.querySelector('.content__wrapper').classList.remove('hide')
    activeTab.querySelector('.content__wrapper').classList.add('show')
}
if (recaptcha_site_key) {
    grecaptcha.ready(() => {
        refresh_recaptcha_token('login_action')
    })
}
const password_reset_action = async(event, retry_count=0) => {
    if (retry_count === 0) {
        event.preventDefault()
    }
    const token = document.getElementById('recaptcha_token').value
    const response = await fetch('/password-reset', {
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
    if (!!json) {
        appMessage(json.status, json.message)
        if (json.status == 'retry') {
            refresh_recaptcha_token('login_action')
            await password_reset_action(event, ++retry_count)
            return;
        } else if (json.status == 'success') {
            document.querySelector('[data-tab="login"]').click()
            document.getElementById('login_email').value = json.email
        }
    }
    refresh_recaptcha_token('login_action')
}
const login_action = async(event, retry_count=0) => {
    if (retry_count === 0) {
        event.preventDefault()
    }
    const login_email = document.getElementById('login_email').value
    const login_password = document.getElementById('password').value
    if (!login_password || !login_email) {
        return;
    }
    const token = document.getElementById('recaptcha_token').value
    const response = await fetch('/login', {
        credentials: 'same-origin',
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
            recaptcha_token: token,
            email: login_email,
            password: login_password
        })
    }).catch(err => {
        appMessage('error', 'An unexpected error occurred. Please refresh the page and try again.')
        console.log(err)
    })
    const json = await response.json()
    if (!!json) {
        appMessage(json.status, json.message)
        if (json.status == 'retry') {
            refresh_recaptcha_token('login_action')
            await login_action(event, ++retry_count)
            return;
        } else if (json.status == 'success') {
            localStorage.setItem('hmac-secret', json.hmac_secret)
            window.location.href = json.is_setup ? '/app' : '/account/setup/1'
        }
    }
    refresh_recaptcha_token('login_action')
}
document.addEventListener('DOMContentLoaded', async() => {
    if (location.pathname != '/login') {
        history.pushState({}, document.title, '/login')
    }
    let activeTabHeight = activeTab.offsetHeight

    // Set height of wrapper on page load
    tabWrapper.style.height = activeTabHeight

    for await(const el of document.querySelectorAll(".tabs > li")) {
        el.addEventListener("click", eventTabSwitch, false)
        el.addEventListener("touchstart", eventTabSwitch, supportsPassive ? { passive: true } : false)
    }

    const appLoginAction = document.getElementById('login_btn')
    if (appLoginAction) {
        appLoginAction.addEventListener('click', login_action, false)
        appLoginAction.addEventListener('touchstart', login_action, supportsPassive ? { passive: true } : false)
    }
    const passwordResetAction = document.getElementById('reset_btn')
    if (passwordResetAction) {
        passwordResetAction.addEventListener('click', password_reset_action, false)
        passwordResetAction.addEventListener('touchstart', password_reset_action, supportsPassive ? { passive: true } : false)
    }

}, false)