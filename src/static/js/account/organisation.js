const bulkAction = async() => {
    const default_role_id = document.getElementById('default_role_id').value
    const bulk_invite = document.getElementById('bulk_invite').value.split('\n')
    const invite_message = document.getElementById('invite_message').value
    const invitationList = document.getElementById('invitation_list')
    for await(const email of bulk_invite) {
        const invite_email = email.replace(/\s/g, '')
        if (invite_email.length === 0) {
            continue
        }
        const json = await Api.post_async('/api/invitation', {
            invite_message,
            invite_email,
            invite_role_id: default_role_id
        }).catch(()=>appMessage('error', 'An unexpected error occurred. Please refresh the page and try again.'))        
        document.getElementById('invitation-list').style = 'display: inline-block;'
        const tmpl = htmlDecode(document.getElementById('tmpl-invitation-list').innerHTML)
        json.invited_by = app.account.email
        json.created_at = (new Date).toLocaleString()
        const row = ejs.render(tmpl, json, {rmWhitespace: true})
        const tr = document.createElement('tr')
        tr.innerHTML = row
        invitationList.insertAdjacentElement('beforeend', tr)
    }
}
const settingsAction = async() => {
    const json1 = await Api.post_async('/api/account', [{
        prop: 'alias',
        value: document.getElementById('alias').value
    }]).catch(()=>appMessage('error', 'An unexpected error occurred. Please refresh the page and try again.'))        
    const json2 = await Api.post_async('/api/account-config', [{
        prop: 'permit_domains',
        value: document.getElementById('permit_domains').value
    }]).catch(()=>appMessage('error', 'An unexpected error occurred. Please refresh the page and try again.'))        
    if (json1.status != 'error' && json2.status != 'error') {
        appMessage('success', `${json1.message} ${json2.message}`)
        return;
    }
    if (json1.status == 'error') {
        appMessage('error', json1.message)
        return;
    }
    if (json2.status == 'error') {
        appMessage('error', json2.message)
        return;
    }
}
const memberAction = async(event) => {
    const member_id = event.currentTarget.parent('tr').getAttribute('data-member-id')
    location.href = `/account/member/${member_id}`
}
const scannerLists = async() => {
    const nameservers = document.getElementById('nameservers').value
    const ignore_list = document.getElementById('ignore_list').value
    const json = await Api.post_async('/api/account-config', [{
        prop: 'nameservers',
        value: nameservers
    },{
        prop: 'ignore_list',
        value: ignore_list
    }]).catch(()=>appMessage('error', 'An unexpected error occurred. Please refresh the page and try again.'))
    appMessage(json.status, json.message)
}

document.addEventListener('DOMContentLoaded', async() => {
    if (location.pathname != '/account/organisation') {
        history.pushState({}, document.title, '/account/organisation')
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
    const settingsEl = document.getElementById('settings-button')
    settingsEl.addEventListener('click', settingsAction, false)
    settingsEl.addEventListener('touchstart', settingsAction, supportsPassive ? { passive: true } : false)
    const bulkEl = document.getElementById('bulk_invite_button')
    bulkEl.addEventListener('click', bulkAction, false)
    bulkEl.addEventListener('touchstart', bulkAction, supportsPassive ? { passive: true } : false)
    for await(const membersEl of document.querySelectorAll('.members-list td')) {
        membersEl.addEventListener('click', memberAction, false)
        membersEl.addEventListener('touchstart', memberAction, supportsPassive ? { passive: true } : false)
    }
    const scannerListsEl = document.getElementById('scanner-lists-button')
    scannerListsEl.addEventListener("click", scannerLists, false)
    scannerListsEl.addEventListener("touchstart", scannerLists, supportsPassive ? { passive: true } : false)

}, false)