const project_tracking_id = document.getElementById('project-tracking-id').value
const project_id = document.getElementById('project-id').value
const page_domain_id = document.getElementById('domain-id').value
let socket, socketio_token, findings_chart;
const subdomainsAction = async event => {
    const id = event.currentTarget.parent('tr').getAttribute('data-domain-id')
    location.href = `/app/domain/${id}`
}
const toggleDomain = async toggleEl => {
    const toggleIconEl = toggleEl.querySelector('i')
    const domain_id = toggleEl.parent('tr').getAttribute('data-domain-id')
    let action = 'enable-domain'
    let classNameAlt = 'icofont-toggle-on'
    if (toggleIconEl.classList.contains('icofont-toggle-on')) {
        classNameAlt = 'icofont-toggle-off'
        action = 'disable-domain'
    }
    const json = await Api.post_async(`/v1/${action}`, {
        domain_id
    }).catch(()=>appMessage('error', 'An unexpected error occurred. Please refresh the page and try again.'))
    if (json.status != 'success') {
        appMessage(json.status, json.message)
        return json
    }
    toggleIconEl.classList.remove(toggleIconEl.className)
    toggleIconEl.classList.add(classNameAlt)
    toggleEl.title = action == 'disable-domain' ? 'Enable domain monitoring' : 'Disable domain monitoring'
    return json
}
const deleteDomain = async domain_id => {
    const json = await Api.post_async(`/v1/delete-domain`, {
        domain_id
    }).catch(()=>appMessage('error', 'An unexpected error occurred. Please refresh the page and try again.'))
    appMessage(json.status, json.message)
    return json
}
const toggleDomainAction = async() => {
    await toggleDomain(document.getElementById('toggle-domain'))
}
const toggleDomainRowAction = async event => {
    await toggleDomain(event.currentTarget)
}
const deleteDomainAction = async() => {
    await deleteDomain(page_domain_id)
}
const deleteDomainRowAction = async event => {
    const domainRow = event.currentTarget.parent('tr')
    const domain_id = domainRow.getAttribute('data-domain-id')
    const json = await deleteDomain(domain_id)
    if (json.status != 'success') {
        return;
    }
    domainRow.remove()
}

const runDomainAction = async event => {
    const action = document.getElementById('scan-action').value
    const json = await Api.post_async(`/v1/${action}`, {
        domain_id: page_domain_id
    }).catch(()=>appMessage('error', 'An unexpected error occurred. Please refresh the page and try again.'))
    appMessage(json.status, json.message)
}
const handleSocket = async data => {
    console.debug(data)
}
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
    const barCanvasEl = document.querySelector('.bar-canvas canvas')
    if (barCanvasEl) {
        findings_chart = new Chart(document.querySelector('.bar-canvas canvas').getContext('2d'), {
            type: 'bar',
            data: findings_chart_config,
            options: {
                indexAxis: 'y',
                scales: {
                    xAxes: [{ ticks: { beginAtZero: true } }]
                },
                layout: {
                    padding: {
                        left: 0,
                        right: 50,
                        top: 0,
                        bottom: 0
                    }
                },
                font: {
                    color: '#e6e6e6'
                }
            }
        })
    }
    const toggleActionEl = document.getElementById('toggle-domain')
    if (toggleActionEl) {
        toggleActionEl.addEventListener('click', toggleDomainAction, false)
        toggleActionEl.addEventListener('touchstart', toggleDomainAction, supportsPassive ? { passive: true } : false)
    }
    const deleteActionEl = document.getElementById('delete-domain')
    deleteActionEl.addEventListener('click', deleteDomainAction, false)
    deleteActionEl.addEventListener('touchstart', deleteDomainAction, supportsPassive ? { passive: true } : false)   
    const runActionEl = document.getElementById('run-action')
    runActionEl.addEventListener('click', runDomainAction, false)
    runActionEl.addEventListener('touchstart', runDomainAction, supportsPassive ? { passive: true } : false)
    for await(const domainEl of document.querySelectorAll('.domains-list td.click-through')) {
        const disabled = domainEl.parent('.disabled-events')
        if (disabled) continue
        domainEl.addEventListener('click', subdomainsAction, false)
        domainEl.addEventListener('touchstart', subdomainsAction, supportsPassive ? { passive: true } : false)
    }
    for await(const domainEl of document.querySelectorAll('.domains-list td.toggle-monitoring')) {
        domainEl.addEventListener('click', toggleDomainRowAction, false)
        domainEl.addEventListener('touchstart', toggleDomainRowAction, supportsPassive ? { passive: true } : false)
    }
    for await(const domainEl of document.querySelectorAll('.domains-list td.delete-domain')) {
        domainEl.addEventListener('click', deleteDomainRowAction, false)
        domainEl.addEventListener('touchstart', deleteDomainRowAction, supportsPassive ? { passive: true } : false)
    }

}, false)
