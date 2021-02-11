const selectAll = async() => {
    for await(const el of document.querySelectorAll('[name="table_finding"]')) {
        if (el.checked) {
            el.checked = false
        } else {
            el.checked = true
        }
    }
}
async function archiveFinding(e) {
    let finding_id;
    let elem;
    if (e.hasOwnProperty('currentTarget')) {
        elem = e.currentTarget
    } else if (e.hasOwnProperty('originalTarget')) {
        elem = e.originalTarget
    } else {
        elem = e.target
    }
    finding_id = elem.value
    if (!finding_id) {
        finding_id = elem.getAttribute('data-finding-id')
    }
    for await(const el of document.querySelectorAll(`tr[data-finding-id="${finding_id}"] td`)) {
        el.style.backgroundColor = 'rgba(0,0,0,0.6)'
    }

    const json = await Api.post_async('/findings', { 'action': 'archive', 'finding_id': finding_id })
        .catch(()=>appMessage('error', 'An unexpected error occurred. Please refresh the page and try again.'))
    appMessage(json)
    for await(const el of document.querySelectorAll(`tr[data-finding-id="${finding_id}"] td`)) {
        el.style.display = 'none'
    }
}

async function resolveFinding(e) {
    const finding_id = e.originalTarget.value
    const reason_text = document.getElementById(`note${finding_id}`).value

    if (!reason_text || reason_text.length < 6) {
        appMessage('error', 'You must supply a reason message for the resolution')
        return;
    }
    const json = await Api.post_async('/findings', { 'action': 'resolve', 'finding_id': finding_id, 'reason': reason_text })
        .catch(()=>appMessage('error', 'An unexpected error occurred. Please refresh the page and try again.'))
    appMessage(json)
    const new_note = `<div class="notes-item">
                    <div class="notes-member">
                        ${app.account.email}
                        <time datetime="${convertDateToUTC(new Date).toISOString()}" title="${(new Date).toLocaleString(window.navigator.userLanguage || window.navigator.language)}"></time>
                    </div>
                    <div class="notes-text">
                        ${reason_text}
                    </div>
                </div>`
    document.querySelector(`.modal-open[data-modal-id="${finding_id}"] .finding-notes-section`).insertAdjacentHTML('beforeend', new_note)
    document.querySelector(`[data-finding-id="${finding_id}"] td:nth-child(10)`).textContent = 'Resolved'
}

async function duplicateFinding(e) {
    const finding_id = e.originalTarget.value
    const json = await Api.post_async('/findings', { 'action': 'workflow', 'finding_id': finding_id, 'workflow_state': 'DUPLICATE' })
        .catch(()=>appMessage('error', 'An unexpected error occurred. Please refresh the page and try again.'))
    appMessage(json)
    for await(const el of document.querySelectorAll(`tr[data-finding-id="${finding_id}"] td`)) {
        el.style.display = 'none'
    }
    for await(const el of document.querySelectorAll('.modal-open')) {
        el.classList.remove('modal-open')
    }
}

async function verifyFinding(e) {
    const finding_id = e.originalTarget.value
    const verification_state = e.originalTarget.getAttribute('name')

    if (!verification_state) {
        appMessage('error', 'You must supply a verification state')
        return;
    }
    const json = await Api.post_async('/findings', { 'action': 'verify', 'finding_id': finding_id, 'verification_state': verification_state })
        .catch(()=>appMessage('error', 'An unexpected error occurred. Please refresh the page and try again.'))
    appMessage(json)
    const states = {
        'true_positive': 'Vulnerable',
        'benign_positive': 'Not Vulnerable',
        'false_positive': 'False Positive',
    }
    document.querySelector(`[data-finding-id="${finding_id}"] td:nth-child(9)`).textContent = states[verification_state]
    if (verification_state != 'true_positive') {
        document.querySelector(`[data-finding-id="${finding_id}"] td:nth-child(10)`).textContent = 'Resolved'
    }
    for await(const el of document.querySelectorAll('.modal-open')) {
        el.classList.remove('modal-open')
    }
}

async function noteFinding(e, note_text, finding_id) {
    if (!finding_id) {
        finding_id = e.originalTarget.value
    }
    if (!note_text) {
        note_text = document.getElementById(`note${finding_id}`).value
    }
    if (!note_text || note_text.length < 3) {
        appMessage('error', 'You must supply a message to create a note')
        return;
    }
    const json = await Api.post_async('/findings', { 'action': 'note', 'finding_id': finding_id, 'text': note_text })
        .catch(()=>appMessage('error', 'An unexpected error occurred. Please refresh the page and try again.'))
    appMessage(json)
    const new_note = `<div class="notes-item">
                    <div class="notes-member">
                        ${app.account.email}
                        <time datetime="${convertDateToUTC(new Date).toISOString()}" title="${(new Date).toLocaleString(window.navigator.userLanguage || window.navigator.language)}"></time>
                    </div>
                    <div class="notes-text">
                        ${note_text}
                    </div>
                </div>`
    document.querySelector(`.modal-open[data-modal-id="${finding_id}"] .finding-notes-section`).insertAdjacentHTML('beforeend', new_note)
    document.querySelector(`[data-finding-id="${finding_id}"] td:nth-child(10)`).textContent = 'In Progress'
}

async function assignFinding(e) {
    const finding_id = e.originalTarget.getAttribute('data-finding-id')
    const assignee_id = e.originalTarget.value
    let action = 'assign'
    if (!assignee_id) {
        action = 'unassign'
    }
    const json = await Api.post_async('/findings', { 'action': action, 'finding_id': finding_id, 'assignee_id': assignee_id })
        .catch(()=>appMessage('error', 'An unexpected error occurred. Please refresh the page and try again.'))
    appMessage(json)
    if (action == 'assign') {
        document.querySelector(`[data-finding-id="${finding_id}"] td:nth-child(10)`).textContent = 'Assigned'
    } else {
        document.querySelector(`[data-finding-id="${finding_id}"] td:nth-child(10)`).textContent = 'New'
    }
}

async function projectFinding(e) {
    const finding_id = e.originalTarget.getAttribute('data-finding-id')
    const project_id = e.originalTarget.value
    const json = await Api.post_async('/findings', { 'action': 'project', 'finding_id': finding_id, 'project_id': project_id })
        .catch(()=>appMessage('error', 'An unexpected error occurred. Please refresh the page and try again.'))
    appMessage(json)
}

async function severityFinding(e) {
    const finding_id = e.originalTarget.getAttribute('data-finding-id')
    const severity = e.originalTarget.value
    const json = await Api.post_async('/findings', { 'action': 'severity', 'finding_id': finding_id, 'severity': severity })
        .catch(()=>appMessage('error', 'An unexpected error occurred. Please refresh the page and try again.'))
    appMessage(json)
}

async function deferFinding(e) {
    const finding_id = e.originalTarget.getAttribute('data-finding-id')
    const defer_date = e.originalTarget.value
    const json = await Api.post_async('/findings', { 'action': 'defer', 'finding_id': finding_id, 'defer': defer_date })
        .catch(()=>appMessage('error', 'An unexpected error occurred. Please refresh the page and try again.'))
    appMessage(json)
    document.querySelector(`[data-finding-id="${finding_id}"] td:nth-child(10)`).textContent = 'Deferred'
}

document.addEventListener('DOMContentLoaded', async() => {
    const ctx1 = document.getElementById('agg_severity_normalized').getContext('2d')
    const ctx2 = document.getElementById('agg_confidence').getContext('2d')
    const ctx3 = document.getElementById('agg_criticality').getContext('2d')
    new Chart(ctx1, {
        type: 'doughnut',
        data: agg_severity_normalized
    })
    new Chart(ctx2, {
        type: 'doughnut',
        data: agg_confidence
    })
    new Chart(ctx3, {
        type: 'doughnut',
        data: agg_criticality
    })
    document.addEventListener('keyup', e => {
        if (e.keyCode == 13 && e.ctrlKey) {
            let ele = document.querySelector('textarea[name="note"]:focus')
            if (ele) {
                let finding_id = ele.getAttribute('id').split('note')[1]
                noteFinding(null, ele.value, finding_id)
                ele.value = ''
            }
        }
    }, false)
    let el = document.getElementById('table_findings')
    el.addEventListener('click', selectAll, false)
    el.addEventListener('touchstart', selectAll, supportsPassive ? { passive: true } : false)
    for await(const elem of document.querySelectorAll('button[name="archive"]')) {
        elem.addEventListener('click', async e => {
            for await(const ele of document.querySelectorAll('.modal-open')) {
                ele.classList.remove('modal-open')
            }
            archiveFinding(e)
        }, false)
        elem.addEventListener('touchstart', async e => {
            for await(const ele of document.querySelectorAll('.modal-open')) {
                ele.classList.remove('modal-open')
            }
            archiveFinding(e)
        }, supportsPassive ? { passive: true } : false)
    }
    for await(const elem of document.querySelectorAll('button[name="resolve-finding"]')) {
        elem.addEventListener('click', resolveFinding, false)
        elem.addEventListener('touchstart', resolveFinding, supportsPassive ? { passive: true } : false)
    }
    for await(const elem of document.querySelectorAll('button[name="true_positive"], button[name="benign_positive"], button[name="false_positive"]')) {
        elem.addEventListener('click', verifyFinding, false)
        elem.addEventListener('touchstart', verifyFinding, supportsPassive ? { passive: true } : false)
    }
    for await(const elem of document.querySelectorAll('button[name="duplicate"]')) {
        elem.addEventListener('click', duplicateFinding, false)
        elem.addEventListener('touchstart', duplicateFinding, supportsPassive ? { passive: true } : false)
    }
    for await(const elem of document.querySelectorAll('select[name="assign"]')) {
        elem.addEventListener('change', assignFinding, false)
    }
    for await(const elem of document.querySelectorAll('select[name="project"]')) {
        elem.addEventListener('change', projectFinding, false)
    }
    for await(const elem of document.querySelectorAll('select[name="severity"]')) {
        elem.addEventListener('change', severityFinding, false)
    }
    for await(const elem of document.querySelectorAll('input[name="defer"]')) {
        elem.addEventListener('change', deferFinding, false)
    }
    for await(const elem of document.querySelectorAll('button[name="finding-note"]')) {
        elem.addEventListener('click', noteFinding, false)
        elem.addEventListener('touchstart', noteFinding, supportsPassive ? { passive: true } : false)
    }
    for await(const elem of document.querySelectorAll('[data-action="archive"]')) {
        elem.addEventListener('click', archiveFinding, false)
        elem.addEventListener('touchstart', archiveFinding, supportsPassive ? { passive: true } : false)
    }

    document.querySelectorAll('select').forEach(ele => { new Choices(ele, { searchEnabled: true }) })
}, false)
