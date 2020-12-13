const editRow = event => {
    const row = event.currentTarget
    const form = document.querySelector('.add_keyvalue_form')
    form.querySelector('[name="value"]').value = row.querySelector('[name="value"]').value
    form.querySelector('[name="key"]').value = row.querySelector('.key-cell').textContent
    form.querySelector('[name="type"]').value = row.querySelector('.type-cell').textContent
    form.querySelector('[name="active_date"]').value = row.querySelector('.active_date-cell').textContent
    form.querySelector('[name="id"]').value = row.getAttribute('data-kv-id')
    form.querySelector('[name="hidden"]').value = row.querySelector('[name="hidden"]').value
}

document.addEventListener('DOMContentLoaded', async(event) => {
    for await(const el of document.querySelectorAll('tr[data-kv-id]')) {
        el.addEventListener('click', editRow, false)
        el.addEventListener('touchstart', editRow, supportsPassive ? { passive: true } : false)
    }
}, false)
