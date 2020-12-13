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
    document.getElementById('password_reset_form').addEventListener('submit', async(e) => {
        e.preventDefault()
        const token = document.getElementById('recaptcha_token').value
        const json = await Api.post_async('/api/password-reset', {
            email: e.currentTarget.querySelector('#email').value,
            recaptcha_token: token
        }).catch(()=>appMessage('error', 'An unexpected error occurred. Please refresh the page and try again.'))
        appMessage(json.status, json.message)
        refresh_recaptcha_token('login_action')
        if (json.status == 'success') {
            document.querySelector('[data-tab="login"]').click()
            document.getElementById('login_email').value = json.email
        }
    }, false)
}, false)