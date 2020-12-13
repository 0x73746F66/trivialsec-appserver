const changeNamespaceList = async(event) => {
    const el = event.currentTarget
    const categoryList = el.value.replace(/ /g, '').toLowerCase()
    if (!categoryList) return;
    const review_id = el.id.replace('type_namespace', '')
    document.getElementById(`type_category${review_id}`).setAttribute('list', categoryList)
}
const changeCategoryList = async(event) => {
    const el = event.currentTarget
    const classifierList = el.value.replace(/ /g, '').toLowerCase()
    if (!classifierList) return;
    const review_id = el.id.replace('type_category', '')
    document.getElementById(`type_classifier${review_id}`).setAttribute('list', classifierList)
}
document.addEventListener('DOMContentLoaded', async() => {
    for await(const el of document.querySelectorAll('[name="type_namespace"]')) {
        el.addEventListener('change', changeNamespaceList, false)
        const categoryList = el.value.replace(/ /g, '').toLowerCase()
        if (categoryList) {
            const review_id = el.id.replace('type_namespace', '')
            document.getElementById(`type_category${review_id}`).setAttribute('list', categoryList)
        }
    }
    for await(const el of document.querySelectorAll('[name="type_category"]')) {
        el.addEventListener('change', changeCategoryList, false)
        const classifierList = el.value.replace(/ /g, '').toLowerCase()
        if (classifierList) {
            const review_id = el.id.replace('type_category', '')
            document.getElementById(`type_classifier${review_id}`).setAttribute('list', classifierList)
        }
    }
    
}, false)
