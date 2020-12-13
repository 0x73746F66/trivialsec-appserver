const update_service_state = data => {
    if (!('service' in data)) {
        console.log(data)
        return;
    }
    const el = document.querySelector(`[data-category="${data.service}"] .service-status`)
    el.classList.remove('service-status-connecting')
    el.classList.remove('service-status-offline')
    el.classList.remove('service-status-idle')
    el.classList.remove('service-status-active')
    if (data.state == 'idle') {
        el.classList.add('service-status-idle')
        el.textContent = 'Idle'
    }
    if (data.state == 'starting' || data.state == 'processing') {
        el.classList.add('service-status-active')
        el.textContent = 'Active'
    }
    if (data.state == 'abort' || data.state == 'error') {
        el.classList.add('service-status-offline')
        el.textContent = 'Offline'
    }
    const category_el = document.querySelector(`[data-category="${data.service}"]`)
    category_el.querySelector('.nodes span').textContent = data.nodes
    category_el.querySelector('.queued span').textContent = data.queued_jobs
    category_el.querySelector('.running span').textContent = data.running_jobs
    category_el.querySelector('.errors span').textContent = data.errored_jobs
    category_el.querySelector('.last-event span').textContent = data.last_event
    category_el.querySelector('.timestamp span').innerHTML = `<time datetime="${convertDateToUTC(new Date).toISOString()}" title="${(new Date).toLocaleString(window.navigator.userLanguage || window.navigator.language)}"></time>`
}
const check_offline = async() => {
    for await(const el of document.querySelectorAll('.service-status-connecting')) {
        el.classList.remove('service-status-connecting')
        el.classList.add('service-status-offline')
        el.textContent = 'Offline'
    }
}
let socket, socketio_token;
document.addEventListener('DOMContentLoaded', () => {
    socketio_token = document.querySelector('[name=socketio_token]').value
    socket = io(`${app.websocket.scheme}${app.websocket.domain}`)
    socket.on('connect', () => {
        console.debug('Connected')
        socket.emit('checkin', socketio_token)
    })
    socket.on('disconnect', (reason) => {
        console.debug(`Disconnected: ${reason}`)
    })
    setTimeout(check_offline, 10000)
    socket.on('update_service_state', update_service_state)
}, false)
