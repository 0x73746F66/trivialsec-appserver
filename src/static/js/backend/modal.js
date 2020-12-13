const closeModal = async event => {
    if (event && !event.target.classList.contains('modal-container') && !event.target.classList.contains('close')) {
        return;
    }
    for await(const el of document.querySelectorAll(`.modal-open`)) {
        if (!el) {
            return;
        }
        el.classList.remove('modal-open')
    }
}

const openModal = async e => {
    if (['I', 'INPUT'].includes(e.target.nodeName)) {
        return;
    }
    const modal_id = e.currentTarget.getAttribute('data-modal-id')
    const el = document.querySelector(`.modal-content[data-modal-id="${modal_id}"]`)
    const modal = el.parent('.modal-container')
    modal.classList.add('modal-open')
    for await(const elem of document.querySelectorAll('.modal-content')) {
        elem.classList.remove('modal-open')
    }
    el.classList.add('modal-open')
    for await (const alert of document.querySelectorAll('#app-messages .alert')) {
        alert.remove()
    }
}

document.addEventListener('DOMContentLoaded', async() => {
    for await(const modal of document.querySelectorAll('.modal-container')) {
        const mcid = String().random()
        modal.setAttribute('data-mcid', mcid)
        modal.addEventListener('click', closeModal, false)
        modal.addEventListener('touchstart', closeModal, supportsPassive ? { passive: true } : false)
}
    for await(const el of document.querySelectorAll('.open-modal')) {
        el.addEventListener('click', openModal, false)
        el.addEventListener('touchstart', openModal, supportsPassive ? { passive: true } : false)
    }
    document.addEventListener('keyup', e => e.keyCode == 27 && closeModal(), false)
}, false)