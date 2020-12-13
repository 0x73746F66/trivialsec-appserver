const domainsAction = async event => {
    const domain_id = event.currentTarget.parent('tr').getAttribute('data-domain-id')
    location.href = `/app/domain/${domain_id}`
}
const projectArchiveButton = async event => {
    document.body.insertAdjacentHTML('afterbegin', `<div class="loading"></div>`)
    const project_id = event.currentTarget.parent('.project-actions').getAttribute('data-project-id')
    const json = await Api.post_async(`/api/archive-project`, {
        project_id
    }).catch(() => {
        appMessage('error', 'An unexpected error occurred. Please refresh the page and try again.')
        document.querySelector('.loading').remove()
    })
    document.querySelector('.loading').remove()
    appMessage(json.status, json.message)
    if (json.status == 'error') {
        return false
    }
}
const handleSocket = async data => {
    console.debug(data)
    if (data.service_category == 'crawler' && data.state == 'completed') {
        const trEl = document.querySelector('tr.disabled-events')
        if (trEl) {
            location.reload()
        }
    }
}
let socket, socketio_token;
document.addEventListener('DOMContentLoaded', async() => {
    socketio_token = document.querySelector('[name=socketio_token]').value
    socket = io(`${app.websocket.scheme}${app.websocket.domain}`)
    socket.on('disconnect', (reason) => {
        console.debug(`Disconnected: ${reason}`)
    })
    socket.on('connect', () => {
        console.debug('Connected')
        socket.emit('checkin', socketio_token)
        for (const tracking_id of trackingIds) {
            socket.emit('checkin', tracking_id)
        }
    })
    socket.on('update_job_state', handleSocket)
    socket.on('dns_changes', handleSocket)
    socket.on('domain_changes', handleSocket)
    socket.on('check_domains_tld', handleSocket)
    const projectActionEl = document.querySelector('.archive-project')
    projectActionEl.addEventListener('click', projectArchiveButton, false)
    projectActionEl.addEventListener('touchstart', projectArchiveButton, supportsPassive ? { passive: true } : false)
    for await(const domainEl of document.querySelectorAll('.domains-list td')) {
        const disabled = domainEl.parent('.disabled-events')
        if (disabled) continue
        domainEl.addEventListener('click', domainsAction, false)
        domainEl.addEventListener('touchstart', domainsAction, supportsPassive ? { passive: true } : false)
    }

}, false)
