# Generated by Django 5.1 on 2024-12-24 18:25

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0002_encryptedimage_encrypted_key_for_owner_and_more'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='SharedImageKey',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('encrypted_key', models.BinaryField()),
                ('key_iv', models.BinaryField()),
                ('image', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='core.encryptedimage')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'unique_together': {('image', 'user')},
            },
        ),
    ]
