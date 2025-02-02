# Generated by Django 4.2.3 on 2023-11-02 17:15

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0009_instance_price'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='routing_number',
            field=models.CharField(blank=True, max_length=9, null=True),
        ),
        migrations.AlterField(
            model_name='cluster',
            name='virtualization',
            field=models.BooleanField(default=True),
        ),
    ]
