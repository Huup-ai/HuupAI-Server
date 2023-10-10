from django.core.management.commands.runserver import Command as RunServerCommand

class Command(RunServerCommand):

    def add_arguments(self, parser):
        super().add_arguments(parser)
        parser.add_argument(
            '-m', '--mode',
            type=str,
            help='Specify a custom mode for the server'
        )

    def handle(self, *args, **options):
        mode = options.get('mode')
        if mode == 'test':
            self.stdout.write(self.style.SUCCESS('Starting server in TEST_MODE...'))
            from django.conf import settings
            setattr(settings, 'TEST_MODE', True)

        super().handle(*args, **options)