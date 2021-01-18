const lang = window.navigator.userLanguage || window.navigator.language
var supportsPassive = false
try {
  let opts = Object.defineProperty({}, 'passive', {
    get: function() {
      supportsPassive = true
    }
  })
  window.addEventListener("testPassive", null, opts)
  window.removeEventListener("testPassive", null, opts)
} catch (e) {}

const sidebarStateKey = 'sidebarState'
let startOnboarding = app.start_onboarding
let sidebarState = localStorage.getItem(sidebarStateKey)
if (!sidebarState) {
    sidebarState = 'sidenav-closed'
}

const siblings = function() {
    let elems = []
    let sibling = this.parentNode.firstChild
    while (sibling) {
        if (sibling.nodeType === 1 && sibling !== this) {
            elems.push(sibling)
        }
        sibling = sibling.nextSibling
    }

    return elems
}
String.prototype.random = (len=16) => {
    return [...Array(len)].map(_=>(Math.random()*32|0).toString(32)).join``
}
EventTarget.prototype.siblings = siblings
Element.prototype.siblings = siblings
Element.prototype.show = function(cb) {
    this.style.display = this.getAttribute('data-css-display') || 'block'
    if (cb) {
        cb.call(this)
    }
}
Element.prototype.hide = function(cb) {
    let originalDisplay = this.getAttribute('data-css-display')
    if (!originalDisplay && this.style.display != 'none') {
        originalDisplay = this.style.display
    }
    this.setAttribute('data-css-display', originalDisplay)
    this.style.display = 'none'
    if (cb) {
        cb.call(this)
    }
}
Element.prototype.remove = function(cb) {
    this.parentNode.removeChild(this)
    if (cb) {
        cb.call(this)
    }
}
Element.prototype.parent = function(selector) {
    let elem = this
	for ( ; elem && elem !== document && elem !== Window; elem = elem.parentNode ) {
		if (elem.matches( selector )) return elem
	}
	return;
}
Array.prototype.clone = function() {
	return this.slice(0)
}
const createUTCDate = d => new Date(Date.UTC(d.getFullYear(), d.getMonth(), d.getDate(), d.getHours(), d.getMinutes(), d.getSeconds()))
const convertDateToUTC = d => new Date(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate(), d.getUTCHours(), d.getUTCMinutes(), d.getUTCSeconds())

const appMessage = (type, str) => {
    const messageTypes = ['warning', 'error', 'info', 'success']
    let obj;
    if (str && messageTypes.includes(type)) {
        obj = {
            status: type,
            message: str
        }
    } else if (type.hasOwnProperty('status') && messageTypes.includes(type['status'])) {
        obj = type
    }
    if (obj) {
        let font;
        if (obj['status'] == 'success') {
            font = 'tick-mark'
        } else {
            font = obj['status']
        }
        const modalAlert = document.querySelector('.modal-open[data-modal-id]')
        if (modalAlert) {
            const alertId = String().random()
            const msgEl = modalAlert.querySelector('.modal-messages')
            msgEl.innerHTML = `<div id="${alertId}" class="alert alert-${obj['status']}"><i class="icofont-${font}"></i>${obj['message']}<i class="icofont-close"></i></div>`
            const alertEl = document.getElementById(alertId)
            const closeEl = alertEl.querySelector('.icofont-close')
            closeEl.addEventListener('click', event => event.currentTarget.parent('.alert').remove(), false)
            closeEl.addEventListener('touchstart', event => event.currentTarget.parent('.alert').remove(), supportsPassive ? { passive: true } : false)
            if (document.querySelectorAll('.modal-open').length > 0) {
                return;
            }
        }
        const appAlert = document.getElementById('app-messages')
        if (appAlert) {
            const msgId = String().random()
            appAlert.innerHTML = `<div id="${msgId}" class="alert alert-${obj['status']}"><i class="icofont-${font}"></i>${obj['message']}<i class="icofont-close"></i></div>`
            const alertEl = document.getElementById(msgId)
            const closeEl = alertEl.querySelector('.icofont-close')
            closeEl.addEventListener('click', event => event.currentTarget.parent('.alert').remove(), false)
            closeEl.addEventListener('touchstart', event => event.currentTarget.parent('.alert').remove(), supportsPassive ? { passive: true } : false)
        }
    }
}
const sidebar = () => {
    document.body.classList.remove('sidenav-open')
    document.body.classList.remove('sidenav-closed')
    document.body.classList.add(sidebarState)
}
const toggler = () => {
    sidebarState = document.body.classList.contains('sidenav-open') ? 'sidenav-closed' : 'sidenav-open'
    localStorage.setItem(sidebarStateKey, sidebarState)
    document.body.classList.toggle('sidenav-open')
    document.body.classList.toggle('sidenav-closed')
}
const livetime = async() => {
    for await(const el of document.querySelectorAll('time')) {
        const utc = createUTCDate(new Date(el.getAttribute('datetime')))
        el.setAttribute('title', utc.toLocaleString(window.navigator.userLanguage || window.navigator.language))
        el.textContent = timeago.format(utc, lang)
    }
}
const validTarget = target => {
    if (validDomain(target)) {
        return true
    }
    if (validIPAddress(target)) {
        return true
    }
    return false
}
const validDomain = domain_name => {
    let re = new RegExp(/^(?!.*?_.*?)(?!^-|.*?\.-.*?|.*?-\..*?)(?!(?:[\d\w]+?\.)?\-[\w\d\.\-]*?)(?![\w\d]+?\-\.(?:[\d\w\.\-]+?))(?=[\w\d])(?=[\w\d\.\-]*?\.+[\w\d\.\-]*?)(?![\w\d\.\-]{254})(?!(?:\.?[\w\d\-\.]*?[\w\d\-]{64,}\.)+?)[\w\d\.\-]+?\.(?![\d]+?$)[\w\d\-]{2,24}$/)
    return re.test(domain_name)
}
const validIPAddress = ip_address => {
    let re = new RegExp(/((^\s*((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))\s*$)|(^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*$))/)
    return re.test(ip_address)
}
const validProject = project_name => {
    let re = new RegExp(/^[\w\d\-\.\ ]{3,255}$/); 
    return re.test(project_name)
}
const htmlDecode = input => {
    let e = document.createElement('textarea')
    e.innerHTML = input
    return e.childNodes.length === 0 ? "" : e.childNodes[0].nodeValue
}

/* API */
const hmac_headers = (http_method, path_uri, json) => {
    const d = new Date
    d.setMilliseconds(0)
    const date = d.toISOString().replace(/.000Z/, "")
    let signing_data = `${http_method}\n${path_uri}\n${date}`
    if (json) {
        signing_data = `${signing_data}\n${btoa(json)}`
    }
    const hmac = forge.hmac.create()
    hmac.start('sha512', localStorage.getItem('hmac-secret'))
    hmac.update(signing_data)
    return {
        'X-Digest': 'HMAC-SHA512',
        'X-ApiKey': app.api.key,
        'X-Date': date,
        'X-Signature': hmac.digest().toHex()
    }
}
const Api = Object.assign({
    get_async: async(path_uri, headers) => {
        const http_method = 'GET'
        const url = `${app.api.scheme}${app.api.domain}${path_uri}`
        const response = await fetch(url, {
            credentials: 'omit',
            method: http_method,
            headers: Object.assign({}, hmac_headers(http_method, path_uri), headers)
        })
        return await response.json()
    },
    get: (path_uri, headers) => {
        const http_method = 'GET'
        const url = `${app.api.scheme}${app.api.domain}${path_uri}`
        return fetch(url, {
            credentials: 'omit',
            method: http_method,
            headers: Object.assign({}, hmac_headers(http_method, path_uri), headers)
        }).then(response => response.json())
    },
    post_async: async(path_uri, data, headers) =>  {
        const http_method = 'POST'
        const url = `${app.api.scheme}${app.api.domain}${path_uri}`
        const json = JSON.stringify(data)
        const response = await fetch(url, {
            credentials: 'omit',
            method: http_method,
            body: json,
            headers: Object.assign({ 'Content-Type': 'application/json' }, hmac_headers(http_method, path_uri, json), headers),
        })
        return await response.json()
    },
    post: (path_uri, data, headers) => {
        const http_method = 'POST'
        const url = `${app.api.scheme}${app.api.domain}${path_uri}`
        const json = JSON.stringify(data)
        return fetch(url, {
            credentials: 'omit',
            method: http_method,
            body: json,
            headers: Object.assign({ 'Content-Type': 'application/json' }, hmac_headers(http_method, path_uri, json), headers),
        }).then(response => response.json())
    }
})
const refresh_recaptcha_token = async(action) => {
    for await(const el of document.querySelectorAll('.wait_recaptcha')) {
        el.disabled = true
    }
    let token = await grecaptcha.execute(recaptcha_site_key, {action})
    document.getElementById('recaptcha_token').value = token
    for await(const el of document.querySelectorAll('.wait_recaptcha')) {
        el.disabled = false
    }

}
const logout_action = async(e) => {
    e.preventDefault()
    localStorage.removeItem('hmac-secret')
    window.location.href = '/logout'
}
document.addEventListener('DOMContentLoaded', async() => {
    for (const closeEl of document.querySelectorAll('.alert .icofont-close')) {
        closeEl.addEventListener('click', event => event.currentTarget.parent('.alert').remove(), false)
        closeEl.addEventListener('touchstart', event => event.currentTarget.parent('.alert').remove(), supportsPassive ? { passive: true } : false)
    }
    const appLogoutAction = document.getElementById('app-logout-action')
    if (appLogoutAction) {
        appLogoutAction.addEventListener('click', logout_action, false)
        appLogoutAction.addEventListener('touchstart', logout_action, supportsPassive ? { passive: true } : false)
    }
}, false)
