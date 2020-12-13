const saveNewEmail = async() => {
    const email = document.getElementById('email').value
    const password = document.getElementById('password').value
    const json = await Api.post_async('/api/update-email', {email, password})
        .catch(()=>appMessage('error', 'An unexpected error occurred. Please refresh the page and try again.'))
    appMessage(json.status, json.message)
}
const changePassword = async() => {
    const repeat_password = document.getElementById('repeat_password').value
    const new_password = document.getElementById('new_password').value
    const old_password = document.getElementById('old_password').value
    if (new_password != repeat_password) {
        appMessage('error', 'Passwords do not match')
        return;
    }
    const json = await Api.post_async('/api/change-password', {old_password, new_password, repeat_password})
        .catch(()=>appMessage('error', 'An unexpected error occurred. Please refresh the page and try again.'))
    appMessage(json.status, json.message)
}

document.addEventListener('DOMContentLoaded', async() => {
    if (location.pathname != '/account/preferences') {
        history.pushState({}, document.title, '/account/preferences')
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
    const emailChangeEl = document.getElementById('change-email-button')
    emailChangeEl.addEventListener("click", saveNewEmail, false)
    emailChangeEl.addEventListener("touchstart", saveNewEmail, supportsPassive ? { passive: true } : false)
    const changePasswordEl = document.getElementById('change-password-button')
    changePasswordEl.addEventListener("click", changePassword, false)
    changePasswordEl.addEventListener("touchstart", changePassword, supportsPassive ? { passive: true } : false)

}, false)