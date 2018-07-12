import argparse
import configparser
import logging
import _client


class BaseCommand(object):
    def __init__(self, namespace):
        self.namespace = namespace
        self.client = None

    def __call__(self):
        self._init_client()
        self.run()

    def _init_client(self):
        self.client = _client.NotesAPIClient(
            self.namespace.get("username"),
            self.namespace.get("password")
        )
        self.client.base_url = self.namespace.get("host", self.client.base_url)

    @classmethod
    def get_parser(cls, parser):
        raise NotImplementedError("Define in derived class!")

    @classmethod
    def get_command(cls, name):
        candidates = filter(
            lambda x: x.__name__ == name,
            cls.__subclasses__()
        )

        return next(candidates)

    def run(self):
        raise NotImplementedError("Define in derived class!")


class ListNote(BaseCommand):

    def run(self):
        format_string = "{:>4} | {}"
        notes = self.client.list_notes()
        if not notes:
            return

        print("=== Notes ===")
        print(format_string.format("ID", "Title"))

        for note in notes:
            print(format_string.format(note.get("id"), note.get("title")))

    @classmethod
    def get_parser(cls, parser):
        parser.add_parser(cls.__name__)


class GetNote(BaseCommand):

    def run(self):
        format_string = "{:10}: {}"
        note = self.client.get_note(self.namespace.get("pk"))

        print("=== Note ({}) ===".format(note.get("id")))
        print(format_string.format("Title", note.get("title")))
        print(format_string.format("Content", note.get("content")))

    @classmethod
    def get_parser(cls, parser):
        subparser = parser.add_parser(cls.__name__)
        subparser.add_argument(
            "pk",
            help="Unique ID of note"
        )


parser = argparse.ArgumentParser(
    description="Secure Notes"
)

authgroup = parser.add_argument_group("Authentication/Server")
authgroup.add_argument(
    "-u", "--username",
    help="Username"
)
authgroup.add_argument(
    "-p", "--password",
    help="Password"
)
authgroup.add_argument(
    "-H", "--host",
    default="http://localhost:8000/notes/",
    help="URL of server"
)

commands = parser.add_subparsers(
    help="Commands",
    dest="command"
)
for command in BaseCommand.__subclasses__():
    command.get_parser(commands)
# list_notes = commands.add_parser("list")

if __name__ == '__main__':
    logging.disable(logging.CRITICAL)
    namespace = vars(parser.parse_args())

    CommandClass = BaseCommand.get_command(namespace.get("command"))
    if issubclass(CommandClass, BaseCommand):
        c = CommandClass(namespace)
        c()