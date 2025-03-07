from datetime import datetime
from trivialsec.models.activity_log import ActivityLog
from trivialsec.models.key_value import KeyValue
from trivialsec.models.feed import Feed
from trivialsec.models.member import Member
from trivialsec.models.finding_detail import FindingDetail


def handle_upsert_feeds(params :dict, member: Member) -> Feed:
    feed = Feed(feed_id=params.get('feed_id'))
    feed.name = params.get('name')
    feed.description = params.get('description')
    feed.url = params.get('url')
    feed.alert_title = params.get('alert_title')
    feed.feed_site = params.get('feed_site')
    feed.abuse_email = params.get('abuse_email')
    feed.disabled = params.get('disabled')
    feed.schedule = params.get('schedule')
    feed.category = params.get('category')
    feed.type = params.get('type')
    feed.method = params.get('method')
    feed.username = params.get('username')
    feed.credential_key = params.get('credential_key')

    if feed.persist():
        ActivityLog(member_id=member.member_id, action='edited_feed', description=feed.name).persist()
        return feed

    return None

def handle_upsert_keyvalues(params :dict, member: Member) -> KeyValue:
    keyvalue = KeyValue(key_value_id=params.get('key_value_id'))
    keyvalue.type = params.get('type')
    keyvalue.key = params.get('key')
    keyvalue.value = params.get('value')
    keyvalue.hidden = params.get('hidden')
    keyvalue.active_date = params.get('active_date')

    if keyvalue.persist():
        ActivityLog(member_id=member.member_id, action='edited_keyvalue', description=keyvalue.key).persist()
        return keyvalue

    return None

def handle_update_recommendations_review(params :dict, member: Member) -> FindingDetail:
    review = FindingDetail(finding_detail_id=params.get('finding_detail_id'))
    review.hydrate()
    review.title = params.get('title')
    review.description = params.get('description')
    review.recommendation = params.get('recommendation')
    review.recommendation_url = params.get('recommendation_url')
    review.type_namespace = params.get('type_namespace')
    review.type_category = params.get('type_category')
    review.type_classifier = params.get('type_classifier')
    review.severity_product = params.get('severity_product')
    review.review = 0
    review.updated_at = datetime.utcnow()
    review.modified_by_id = member.member_id

    if review.persist():
        ActivityLog(member_id=member.member_id, action='edited_finding_detail', description=review.finding_detail_id).persist()
        return review

    return None
