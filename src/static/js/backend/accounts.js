const selectAll = async() => {
    for await(const el of document.querySelectorAll('[name="table_account"]')) {
        if (el.checked) {
            el.checked = false
        } else {
            el.checked = true
        }
    }
}

document.addEventListener('DOMContentLoaded', event => {

    let el = document.getElementById('table_accounts')
    el.addEventListener('click', selectAll, false)
    el.addEventListener('touchstart', selectAll, supportsPassive ? { passive: true } : false)

    document.querySelectorAll('select').forEach(el => { new Choices(el, { searchEnabled: true }) })
}, false)