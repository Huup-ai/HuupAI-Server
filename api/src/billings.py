
from ..models import *
from ..serializers import *
from datetime import timedelta
from django.utils import timezone
from django.db import transaction
import json
import stripe


def daily_billing():
    stripe.api_key = 'sk_test_51NT86tLM79TglgywZ5DMu5q9nOyWvxzDLbdqLOeAClOAYRa823nz347d4kiNJ6TbTCLL03MQYlGllK0ooGZHcdAG00H48pWjm0'  # Set your Stripe secret key

    today = timezone.now().date()
    one_month_ago = today - timedelta(days=30)
    
    for user in User.objects.filter(invoice_date=one_month_ago):
        instances = Instance.objects.filter(user_id=user)

        total_amount_to_charge = 0  # Initialize total amount to charge the user
        invoices = []  # List to store created invoices
        
        with transaction.atomic():
            for instance in instances:
                try:
                    new_usage = instance.usage
                    if instance.status != 'terminated':
                        time_delta = timezone.now() - instance.start_time
                        new_usage += time_delta.total_seconds() / 3600  # Calculate usage in hours

                    usage_hours = round(new_usage, 2)
                    tax = user.tax
                    total_price = round(instance.price * usage_hours + tax, 2)
                    total_amount_to_charge += total_price  # Accumulate the amount
                    
                    # Create an invoice with this data
                    invoice = Invoice.objects.create(
                        user=user,
                        instance=instance,
                        invoice_time=timezone.now(),
                        price=instance.price,
                        usage=usage_hours,
                        tax=tax,
                        total_price=total_price,
                        paid=False
                    )
                    invoices.append(invoice)
                    
                    instance.usage = 0.0
                    instance.start_time = timezone.now()
                    
                except Exception as e:
                    # Handle exception appropriately (Logging recommended)
                    print(f"Error processing instance ID {instance.id}: {e}")
            
            # Charge the user using Stripe
            try:
                stripe_customer = StripeCustomer.objects.get(user=user)
                
                payment_intent = stripe.PaymentIntent.create(
                    amount=int(total_amount_to_charge * 100),  # Amount in cents
                    currency='usd',  # Set to your preferred currency
                    customer=stripe_customer.stripe_customer_id,
                    payment_method=stripe_customer.stripe_payment
                )

                # Check payment status and update invoices accordingly
                if payment_intent.status == "succeeded":
                    for invoice in invoices:
                        invoice.paid = True
                        invoice.save()
                
            except StripeCustomer.DoesNotExist:
                print(f"User ID {user.id} does not have an associated Stripe Customer.")
            except stripe.error.StripeError as e:
                print(f"Stripe error for User ID {user.id}: {e}")

            # Save changes
            user.invoice_date = today
            user.save()