const subdomainsAction = async() => {
    const json = await Api.post_async('/api/account-config', [{
        prop: 'alienvault',
        value: document.querySelector('[name="alienvault"]').value
    },{
        prop: 'binaryedge',
        value: document.querySelector('[name="binaryedge"]').value
    },{
        prop: 'c99',
        value: document.querySelector('[name="c99"]').value
    },{
        prop: 'censys_key',
        value: document.querySelector('[name="censys_key"]').value
    },{
        prop: 'censys_secret',
        value: document.querySelector('[name="censys_secret"]').value
    },{
        prop: 'chaos',
        value: document.querySelector('[name="chaos"]').value
    },{
        prop: 'cloudflare',
        value: document.querySelector('[name="cloudflare"]').value
    },{
        prop: 'circl_user',
        value: document.querySelector('[name="circl_user"]').value
    },{
        prop: 'circl_pass',
        value: document.querySelector('[name="circl_pass"]').value
    },{
        prop: 'dnsdb',
        value: document.querySelector('[name="dnsdb"]').value
    },{
        prop: 'facebookct_key',
        value: document.querySelector('[name="facebookct_key"]').value
    },{
        prop: 'facebookct_secret',
        value: document.querySelector('[name="facebookct_secret"]').value
    },{
        prop: 'networksdb',
        value: document.querySelector('[name="networksdb"]').value
    },{
        prop: 'recondev_free',
        value: document.querySelector('[name="recondev_free"]').value
    },{
        prop: 'passivetotal_key',
        value: document.querySelector('[name="passivetotal_key"]').value
    },{
        prop: 'passivetotal_user',
        value: document.querySelector('[name="passivetotal_user"]').value
    },{
        prop: 'securitytrails',
        value: document.querySelector('[name="securitytrails"]').value
    },{
        prop: 'shodan',
        value: document.querySelector('[name="shodan"]').value
    },{
        prop: 'spyse',
        value: document.querySelector('[name="spyse"]').value
    },{
        prop: 'twitter_key',
        value: document.querySelector('[name="twitter_key"]').value
    },{
        prop: 'twitter_secret',
        value: document.querySelector('[name="twitter_secret"]').value
    },{
        prop: 'urlscan',
        value: document.querySelector('[name="urlscan"]').value
    },{
        prop: 'umbrella',
        value: document.querySelector('[name="umbrella"]').value
    },{
        prop: 'virustotal',
        value: document.querySelector('[name="virustotal"]').value
    },{
        prop: 'whoisxml',
        value: document.querySelector('[name="whoisxml"]').value
    },{
        prop: 'zetalytics',
        value: document.querySelector('[name="zetalytics"]').value
    },{
        prop: 'zoomeye',
        value: document.querySelector('[name="zoomeye"]').value
    }]).catch(()=>appMessage('error', 'An unexpected error occurred. Please refresh the page and try again.'))        
    appMessage(json.status, json.message)
    if (json.status == 'error') {
        return;
    }
}
const reposAction = async() => {
    const json = await Api.post_async('/api/account-config', [{
        prop: 'github_key',
        value: document.querySelector('[name="github_key"]').value
    },{
        prop: 'github_user',
        value: document.querySelector('[name="github_user"]').value
    },{
        prop: 'gitlab',
        value: document.querySelector('[name="gitlab"]').value
    }]).catch(()=>appMessage('error', 'An unexpected error occurred. Please refresh the page and try again.'))        
    appMessage(json.status, json.message)
    if (json.status == 'error') {
        return;
    }
}
document.addEventListener('DOMContentLoaded', async() => {
    if (location.pathname != '/account/integrations') {
        history.pushState({}, document.title, '/account/integrations')
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
    const subdomainsEl = document.getElementById('subdomains-button')
    subdomainsEl.addEventListener('click', subdomainsAction, false)
    subdomainsEl.addEventListener('touchstart', subdomainsAction, supportsPassive ? { passive: true } : false)

    const reposEl = document.getElementById('source-code-button')
    reposEl.addEventListener('click', reposAction, false)
    reposEl.addEventListener('touchstart', reposAction, supportsPassive ? { passive: true } : false)

}, false)