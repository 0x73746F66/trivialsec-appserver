from decimal import Decimal, ROUND_DOWN
import json
import stripe
from flask import Blueprint, jsonify, request
from gunicorn.glogging import logging
from trivialsec.helpers.config import config
from trivialsec.models.account import Account
from trivialsec.models.plan import Plan
from trivialsec.helpers.payments import upsert_plan_invoice, payment_intent_succeeded, invoice_paid, subscription_created


logger = logging.getLogger(__name__)
blueprint = Blueprint('webhook', __name__)

@blueprint.route('/stripe', methods=['POST'])
def wh_stripe():
    # You can use webhooks to receive information about asynchronous payment events.
    # For more about our webhook events check out https://stripe.com/docs/webhooks.
    webhook_secret = config.stripe_webhook_secret
    request_data = json.loads(request.data)

    if webhook_secret:
        # Retrieve the event by verifying the signature using the raw body and secret if webhook signing is configured.
        signature = request.headers.get('stripe-signature')
        try:
            event = stripe.Webhook.construct_event(
                payload=request.data, sig_header=signature, secret=webhook_secret)
            data = event['data']['object']
        except Exception as ex:
            logger.exception(ex)
            return jsonify({'status': 'error'})
        # Get the type of webhook event sent - used to check the status of PaymentIntents.
        event_type = event['type']
    else:
        data = request_data['data']['object']
        event_type = request_data['type']

    logger.warning(f'[{event_type}]\n{data}')
    return jsonify({'plan_id': webhook_received(event_type, data)})

def webhook_received(event_type :str, stripe_data :dict) -> int:
    if event_type == 'payment_intent.succeeded':
        return payment_intent_succeeded(stripe_data.get('customer'), stripe_data['charges']['data'][0])

    if event_type == 'invoice.paid':
        return invoice_paid(stripe_data.get('customer'), stripe_data)

    if event_type in ['invoice.updated', 'invoice.payment_succeeded']:
        return upsert_plan_invoice(stripe_data)

    if event_type == 'invoice.payment_failed':
        plan = Plan(stripe_customer_id=stripe_data['customer'])
        plan.hydrate('stripe_customer_id')
        account = Account(account_id=plan.account_id)
        account.hydrate()
        if account.is_setup is True:
            account.is_setup = False
            account.persist()
        return plan.plan_id

    if event_type == 'customer.subscription.deleted':
        plan = Plan(stripe_customer_id=stripe_data['customer'])
        plan.hydrate('stripe_customer_id')
        account = Account(account_id=plan.account_id)
        account.hydrate()
        if account.is_setup is True:
            account.is_setup = False
            account.persist()
        return plan.plan_id

    if event_type == 'customer.subscription.created':
        return subscription_created(
            stripe_customer=stripe_data.get('customer'),
            stripe_subscription_id=stripe_data.get('id'),
            default_payment_method=stripe_data.get('default_payment_method'),
            stripe_plan_data=stripe_data['items']['data'][0]['plan']
        )
