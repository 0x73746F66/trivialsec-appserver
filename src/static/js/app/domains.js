const domainsAction = async event => {
    const domain_id = event.currentTarget.parent('tr').getAttribute('data-domain-id')
    location.href = `/app/domain/${domain_id}`
}
document.addEventListener('DOMContentLoaded', async() => {
    for await(const projectsEl of document.querySelectorAll('.domains-list td')) {
        projectsEl.addEventListener('click', domainsAction, false)
        projectsEl.addEventListener('touchstart', domainsAction, supportsPassive ? { passive: true } : false)
    }

}, false)
