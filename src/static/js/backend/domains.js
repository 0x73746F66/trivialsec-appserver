const addDomain = async () => {
    const domain_el = document.getElementById('domain_search_input')
    const project_el = document.getElementById('project_select')
    const json = await Api.post_async('/domains', { 'domain': domain_el.value, 'project_id': project_el.value })
        .catch(()=>appMessage('error', 'An unexpected error occurred. Please refresh the page and try again.'))
    appMessage(json)
    if ('id' in json['domain']) {
        let tr = `<tr class="highlight" data-domain-id="${json['domain']['id']}">
        <td><input type="checkbox" name="table_domains" value="${json['domain']['id']}"></td>
        <td><a href="/scope/${json['domain']['project_id']}">${json['project']['name']}</a></td>
        <td><a href="/domain/1">${json['domain']['name']}</a></td>
        <td>None 0 (0bytes)</td>
        <td>None</td>
        <td>None</td>
        <td></td>
        <td>Ensure the DNS TXT record includes:<br><pre>trivialsec=${json['domain']['verification_hash']}</pre></td>
        <td>None</td>
    </tr>`
        document.querySelector('#domains-list tbody').insertAdjacentHTML('beforeend', tr)
    }
}

const searchDomain = async event => {
    const domain_name = event.currentTarget.value
    const json = await Api.get_async(`/domains/search/${domain_name}`)
        .catch(()=>appMessage('error', 'An unexpected error occurred. Please refresh the page and try again.'))
    const el = document.getElementById('add_domain')
    if (json.hasOwnProperty('id') && json['id']) {
        const row = document.querySelector(`[data-domain-id="${json['id']}"]`)
        if (row) {
            row.classList.add('flash-row')
            setTimeout(() => row.classList.remove('flash-row'), 2000)
        }
        appMessage('warning', `${domain_name} is already registered`)
        el.disabled = true
    } else {
        appMessage(json)
        el.disabled = false
    }
}

document.addEventListener('DOMContentLoaded', () => {
    // let el = document.getElementById('add_domain')
    // el.addEventListener('click', addDomain, false)
    // el.addEventListener('touchstart', addDomain, supportsPassive ? { passive: true } : false)
    // el = document.getElementById('domain_search_input')
    // el.addEventListener('change', searchDomain, false)
    // el.addEventListener('blur', searchDomain, false)
}, false)