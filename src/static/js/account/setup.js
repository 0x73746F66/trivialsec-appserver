const setupActions = async(event) => {
    if (event.currentTarget.classList.contains('skip')) {
        skipSection(event)
        return;
    }
    if (event.currentTarget.id == 'step1') {
        saveFields(event, [{
            prop: 'alias',
            value: document.querySelector('[name="account_alias"]').value
        }], '/v1/account')
        saveFields(event, [{
            prop: 'default_role_id',
            value: document.querySelector('[name="default_role_id"]').value
        }])
        return;
    }
    if (event.currentTarget.id == 'permit_domains') {
        let value = document.querySelector('[name="permit_domains"]').value
        saveFields(event, [{prop: 'permit_domains', value}])
        return;
    }
    if (event.currentTarget.id == 'blacklist_domains') {
        let value = document.querySelector('[name="blacklisted_domains"]').value
        saveFields(event, [{prop: 'blacklisted_domains', value}])
        return;
    }
    if (event.currentTarget.id == 'blacklist_ips') {
        let value = document.querySelector('[name="blacklisted_ips"]').value
        saveFields(event, [{prop: 'blacklisted_ips', value}])
        return;
    }
    if (event.currentTarget.id == 'nameservers') {
        let value = document.querySelector('[name="nameservers"]').value
        saveFields(event, [{prop: 'nameservers', value}])
        return;
    }
    if (event.currentTarget.id == 'urlscan') {
        let value = document.querySelector('[name="urlscan"]').value
        saveFields(event, [{prop: 'urlscan', value}])
        return;
    }
    if (event.currentTarget.id == 'github') {
        let value = document.querySelector('[name="github"]').value
        saveFields(event, [{prop: 'github', value}])
        return;
    }
    if (event.currentTarget.id == 'gitlab') {
        let value = document.querySelector('[name="gitlab"]').value
        saveFields(event, [{prop: 'gitlab', value}])
        return;
    }
    if (event.currentTarget.id == 'alienvault') {
        let value = document.querySelector('[name="alienvault"]').value
        saveFields(event, [{prop: 'alienvault', value}])
        return;
    }
    if (event.currentTarget.id == 'binaryedge') {
        let value = document.querySelector('[name="binaryedge"]').value
        saveFields(event, [{prop: 'binaryedge', value}])
        return;
    }
    if (event.currentTarget.id == 'c99') {
        let value = document.querySelector('[name="c99"]').value
        saveFields(event, [{prop: 'c99', value}])
        return;
    }
    if (event.currentTarget.id == 'censys') {
        let key = document.querySelector('[name="censys_key"]').value
        let secret = document.querySelector('[name="censys_secret"]').value
        saveFields(event, [{prop: 'censys_key', value: key}, {prop: 'censys_secret', value: secret}])
        return;
    }
    if (event.currentTarget.id == 'chaos') {
        let value = document.querySelector('[name="chaos"]').value
        saveFields(event, [{prop: 'chaos', value}])
        return;
    }
    if (event.currentTarget.id == 'circl') {
        let key = document.querySelector('[name="circl_user"]').value
        let secret = document.querySelector('[name="circl_pass"]').value
        saveFields(event, [{prop: 'circl_user', value: key}, {prop: 'circl_pass', value: secret}])
        return;
    }
    if (event.currentTarget.id == 'dnsdb') {
        let value = document.querySelector('[name="dnsdb"]').value
        saveFields(event, [{prop: 'dnsdb', value}])
        return;
    }
    if (event.currentTarget.id == 'facebookct') {
        let key = document.querySelector('[name="facebookct_key"]').value
        let secret = document.querySelector('[name="facebookct_secret"]').value
        saveFields(event, [{prop: 'facebookct_key', value: key}, {prop: 'facebookct_secret', value: secret}])
        return;
    }
    if (event.currentTarget.id == 'networksdb') {
        let value = document.querySelector('[name="networksdb"]').value
        saveFields(event, [{prop: 'networksdb', value}])
        return;
    }
    if (event.currentTarget.id == 'passivetotal') {
        let key = document.querySelector('[name="passivetotal_key"]').value
        let secret = document.querySelector('[name="passivetotal_user"]').value
        saveFields(event, [{prop: 'passivetotal_key', value: key}, {prop: 'passivetotal_user', value: secret}])
        return;
    }
    if (event.currentTarget.id == 'securitytrails') {
        let value = document.querySelector('[name="securitytrails"]').value
        saveFields(event, [{prop: 'securitytrails', value}])
        return;
    }
    if (event.currentTarget.id == 'shodan') {
        let value = document.querySelector('[name="shodan"]').value
        saveFields(event, [{prop: 'shodan', value}])
        return;
    }
    if (event.currentTarget.id == 'spyse') {
        let value = document.querySelector('[name="spyse"]').value
        saveFields(event, [{prop: 'spyse', value}])
        return;
    }
    if (event.currentTarget.id == 'twitter') {
        let key = document.querySelector('[name="twitter_key"]').value
        let secret = document.querySelector('[name="twitter_secret"]').value
        saveFields(event, [{prop: 'twitter_key', value: key}, {prop: 'twitter_secret', value: secret}])
        return;
    }
    if (event.currentTarget.id == 'umbrella') {
        let value = document.querySelector('[name="umbrella"]').value
        saveFields(event, [{prop: 'umbrella', value}])
        return;
    }
    if (event.currentTarget.id == 'virustotal') {
        let value = document.querySelector('[name="virustotal"]').value
        saveFields(event, [{prop: 'virustotal', value}])
        return;
    }
    if (event.currentTarget.id == 'whoisxml') {
        let value = document.querySelector('[name="whoisxml"]').value
        saveFields(event, [{prop: 'whoisxml', value}])
        return;
    }
    if (event.currentTarget.id == 'zetalytics') {
        let value = document.querySelector('[name="zetalytics"]').value
        saveFields(event, [{prop: 'zetalytics', value}])
        return;
    }
    if (event.currentTarget.id == 'verification') {
        const domain_name = document.querySelector('[name="verify_domains"]').value
        let timeout = setTimeout(() => {
            appMessage('error', `Domain [${domain_name}] verification check failed`)
            verificationEl.textContent = 'Error'
        }, 10000)
        Api.get(`/v1/domain-verify/${domain_name}`).then(json => {
            clearTimeout(timeout)
            if (!json.registered) {
                appMessage('warning', `Unregistered Domain ${domain_name}`)
                console.error(json.error)
                return;
            }
            if (!json.result && json.error) {
                appMessage('warning', `Domain [${domain_name}] verification check failed: ${json.error}`)
                console.error(json.error)
                return false;
            }
            if (json.result) {
                appMessage('success', `Domain ${domain_name} Verified`)
            } else {
                appMessage('info', `Domain ${domain_name} Unverified`)
            }
        })
    }
    if (event.currentTarget.id == 'invite') {
        const invite_email = document.getElementById('invite_email').value
        const invite_role_id = document.getElementById('invite_role_id').value
        const invite_message = document.getElementById('invite_message').value
        const invitationList = document.getElementById('invitation_list')
        const json = await Api.post_async('/v1/invitation', {invite_email, invite_role_id, invite_message})
            .catch(()=>appMessage('error', 'An unexpected error occurred. Please refresh the page and try again.'))        
        appMessage(json.status, json.message)
        if (json.status == 'error') {
            return;
        }
        const tmpl = htmlDecode(document.getElementById('tmpl-invitation-list').innerHTML)
        const row = ejs.render(tmpl, json, {rmWhitespace: true})
        const tr = document.createElement('tr')
        tr.innerHTML = row
        invitationList.insertAdjacentElement('beforeend', tr)
    }
}
const saveFields = async(event, data, uri='/v1/account-config') => {
    const json = await Api.post_async(uri, data).catch(()=>appMessage('error', 'An unexpected error occurred. Please refresh the page and try again.'))
    appMessage(json.status, json.message)
    if (json.status == 'error') {
        console.log(json)
    }
}
const skipSection = event => {
    let nextStep, step;
    const section = event.target.parent('.setup-section')
    const parent = section.parentNode
    section.remove()
    if (parent.classList.contains('step-1')) {
        step = 1
        nextStep = 2
    }
    if (parent.classList.contains('step-2')) {
        step = 2
        nextStep = 3
    }
    if (parent.classList.contains('step-3')) {
        step = 3
        nextStep = 4
    }
    if (parent.classList.contains('step-4')) {
        step = 4
        nextStep = 5
    }
    if (parent.classList.contains('step-5')) {
        step = 5
        nextStep = 6
    }
    
    setTimeout(()=>{window.location.href = `/account/setup/${nextStep}`}, 2000)
    // Api.post('/v1/account', [{prop: 'is_setup', value: 1}]).then(json => {
    //     if (json.status == 'error') {
    //         console.log(json)
    //     }
    //     if (json.status == 'success') {
    //         setTimeout(()=>{window.location.href = '/app'}, 2000)
    //     }
    // })
}

document.addEventListener('DOMContentLoaded', async() => {
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
    for await(const el of document.querySelectorAll('button')) {
        el.addEventListener('click', setupActions, false)
        el.addEventListener('touchstart', setupActions, supportsPassive ? { passive: true } : false)
    }
    for await(const el of document.querySelectorAll('.step-1 .setup-section')) {
        el.classList.add('active')
    }
}, false)